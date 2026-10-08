"""
피싱 URL 판별 RAG 웹 서비스

동작 방식:
    1. 입력 URL에서 preprocess.py의 extract_features()로 특징 추출
    2. build_vector_store.py와 동일한 방식으로 자연어 설명을 만들어 임베딩
    3. FAISS 벡터 스토어에서 유사한 과거 URL(피싱/정상 라벨 포함) k개 검색 (Retrieval)
    4. 검색된 사례를 근거(context)로 삼아 Claude에게 최종 판정 + 근거 설명 요청 (Generation)
    5. JSON으로 판정 결과 반환

사전 준비:
    1) preprocess.py 로 features_output.csv 생성
    2) build_vector_store.py 로 vector_store 폴더(FAISS 인덱스) 생성
    3) 환경변수 ANTHROPIC_API_KEY 설정
    4) 이 파일을 preprocess.py와 같은 폴더에 두고 실행:
         uvicorn rag_app:app --reload

사용법 (예시):
    curl -X POST http://localhost:8000/check \
        -H "Content-Type: application/json" \
        -d '{"url": "http://paypal-verify-account.tk/login"}'
"""

import json
import os

import faiss
import pandas as pd
from anthropic import Anthropic
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

from preprocess import extract_features  # 기존 preprocess.py 재사용 (같은 폴더에 있어야 함)

INDEX_DIR = os.environ.get("RAG_INDEX_DIR", "vector_store")
TOP_K = int(os.environ.get("RAG_TOP_K", 5))
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
CLAUDE_MODEL = "claude-sonnet-4-6"

app = FastAPI(title="피싱 URL 판별 RAG 서비스")

# ---------------------------------------------------------------------------
# 서버 시작 시 1회만 로드 (매 요청마다 로드하면 느려짐)
# ---------------------------------------------------------------------------
print("임베딩 모델 로드 중...")
embed_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

print("FAISS 인덱스 로드 중...")
_index_path = os.path.join(INDEX_DIR, "phishing_index.faiss")
_meta_path = os.path.join(INDEX_DIR, "metadata.jsonl")
if not os.path.exists(_index_path) or not os.path.exists(_meta_path):
    raise FileNotFoundError(
        f"'{INDEX_DIR}'에서 벡터 스토어를 찾을 수 없습니다. "
        "먼저 build_vector_store.py를 실행하세요."
    )
faiss_index = faiss.read_index(_index_path)
metadata_df = pd.read_json(_meta_path, lines=True)

print("Anthropic 클라이언트 초기화 중...")
claude_client = Anthropic()  # ANTHROPIC_API_KEY 환경변수를 자동으로 사용


class URLRequest(BaseModel):
    url: str


def row_to_description(feats: dict) -> str:
    """extract_features() 결과를 build_vector_store.py와 동일한 형식의 설명으로 변환."""
    parts = [
        f"URL: {feats['url']}",
        f"URL 길이: {feats['url_length']}",
        f"호스트 길이: {feats['host_length']}",
        f"서브도메인 개수: {feats['subdomain_count']}",
        f"특수문자 비율: {feats['special_char_ratio']}",
        f"숫자 비율: {feats['digit_ratio']}",
        f"IP 도메인 여부: {'예' if feats['is_ip_domain'] else '아니오'}",
        f"퓨니코드 사용 여부: {'예' if feats['has_punycode'] else '아니오'}",
        f"의심 키워드 개수: {feats['suspicious_keyword_count']}",
        f"단축 URL 여부: {'예' if feats['is_shortener'] else '아니오'}",
        f"URL 엔트로피: {feats['url_entropy']}",
        f"호스트 엔트로피: {feats['host_entropy']}",
        f"대시(-) 개수: {feats['count_dash']}",
        f"골뱅이(@) 개수: {feats['count_at']}",
    ]
    return " / ".join(parts)


def retrieve_similar_cases(description: str, k: int = TOP_K) -> pd.DataFrame:
    """설명 텍스트를 임베딩해 FAISS에서 유사 사례 k개를 검색."""
    query_vec = embed_model.encode(
        [description], convert_to_numpy=True, normalize_embeddings=True
    ).astype("float32")
    scores, indices = faiss_index.search(query_vec, k)
    results = metadata_df.iloc[indices[0]].copy()
    results["similarity"] = scores[0]
    return results


def build_context_block(similar_cases: pd.DataFrame) -> str:
    """검색된 유사 사례들을 프롬프트에 넣을 텍스트 블록으로 변환."""
    lines = []
    for i, row in enumerate(similar_cases.itertuples(), start=1):
        label_text = "피싱" if row.label == 1 else "정상"
        lines.append(
            f"{i}. (유사도 {row.similarity:.3f}, 실제 라벨: {label_text}) {row.description}"
        )
    return "\n".join(lines)


def ask_claude_for_verdict(target_description: str, context_block: str) -> dict:
    """검색된 유사 사례를 근거로 Claude에게 최종 판정을 요청."""
    system_prompt = (
        "당신은 피싱 URL 탐지 전문가입니다. 아래에 주어지는 '유사 사례'는 "
        "과거에 실제로 피싱/정상으로 판명난 URL들과 그 특징입니다. 이 사례들을 "
        "참고 근거로 삼아, 새로 주어지는 대상 URL이 피싱인지 정상인지 판정하세요. "
        "반드시 아래 JSON 형식으로만 답하세요. 다른 텍스트를 추가하지 마세요.\n"
        '{"verdict": "phishing" 또는 "normal", "confidence": 0~1 사이 숫자, '
        '"reason": "판정 근거를 한국어로 2~3문장 요약"}'
    )
    user_prompt = (
        f"[대상 URL 특징]\n{target_description}\n\n"
        f"[유사 사례 (검색된 근거)]\n{context_block}"
    )

    response = claude_client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=500,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    raw_text = response.content[0].text.strip()
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        # 모델이 형식을 어겼을 때를 대비한 폴백
        return {"verdict": "unknown", "confidence": 0.0, "reason": raw_text}


@app.post("/check")
def check_url(request: URLRequest):
    """URL 하나를 받아 RAG 기반 피싱 여부 판정을 반환."""
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url이 비어 있습니다.")

    # 1) 특징 추출 (preprocess.py 재사용)
    feats = extract_features(url)
    description = row_to_description(feats)

    # 2) 유사 사례 검색 (Retrieval)
    similar_cases = retrieve_similar_cases(description, k=TOP_K)
    context_block = build_context_block(similar_cases)

    # 3) Claude에게 최종 판정 요청 (Generation)
    verdict = ask_claude_for_verdict(description, context_block)

    return {
        "url": url,
        "verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
        "reason": verdict.get("reason"),
        "extracted_features": feats,
        "similar_cases": similar_cases[["url", "label", "similarity"]].to_dict(orient="records"),
    }


@app.get("/health")
def health():
    return {"status": "ok", "indexed_urls": len(metadata_df)}
