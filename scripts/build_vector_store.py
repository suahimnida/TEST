import argparse
import os

import faiss
import pandas as pd
from sentence_transformers import SentenceTransformer

EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def row_to_description(row: pd.Series) -> str:
    label_text = "피싱(phishing)" if row["label"] == 1 else "정상(legitimate)"
    parts = [
        f"URL: {row['url']}",
        f"라벨: {label_text}",
        f"URL 길이: {int(row['url_length'])}",
        f"호스트 길이: {int(row['host_length'])}",
        f"서브도메인 개수: {int(row['subdomain_count'])}",
        f"특수문자 비율: {row['special_char_ratio']}",
        f"숫자 비율: {row['digit_ratio']}",
        f"IP 도메인 여부: {'예' if row['is_ip_domain'] else '아니오'}",
        f"퓨니코드 사용 여부: {'예' if row['has_punycode'] else '아니오'}",
        f"의심 키워드 개수: {int(row['suspicious_keyword_count'])}",
        f"단축 URL 여부: {'예' if row['is_shortener'] else '아니오'}",
        f"URL 엔트로피: {row['url_entropy']}",
        f"호스트 엔트로피: {row['host_entropy']}",
        f"대시(-) 개수: {int(row['count_dash'])}",
        f"골뱅이(@) 개수: {int(row['count_at'])}",
    ]
    return " / ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="특징 CSV로부터 RAG 벡터 스토어 구축")
    parser.add_argument("--input", required=True, help="preprocess.py로 생성한 features_output.csv 경로")
    parser.add_argument("--index-dir", default="vector_store", help="인덱스/메타데이터 저장 폴더")
    args = parser.parse_args()

    print(f"[1/4] 특징 데이터 로드: {args.input}")
    df = pd.read_csv(args.input)

    print("[2/4] 임베딩용 설명 텍스트 생성 중...")
    df["description"] = df.apply(row_to_description, axis=1)

    print(f"[3/4] 임베딩 모델 로드 및 벡터화 중 ({EMBEDDING_MODEL_NAME})...")
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    embeddings = model.encode(
        df["description"].tolist(),
        batch_size=64,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True, 
    ).astype("float32")

    print("[4/4] FAISS 인덱스 생성 및 저장 중...")
    os.makedirs(args.index_dir, exist_ok=True)
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim) 
    index.add(embeddings)
    faiss.write_index(index, os.path.join(args.index_dir, "phishing_index.faiss"))

    meta_cols = [
        "url", "label", "description", "url_length", "special_char_ratio",
        "digit_ratio", "is_ip_domain", "has_punycode",
        "suspicious_keyword_count", "is_shortener", "url_entropy",
    ]
    df[meta_cols].to_json(
        os.path.join(args.index_dir, "metadata.jsonl"),
        orient="records",
        lines=True,
        force_ascii=False,
    )

    print(f"\n완료: {len(df)}건의 URL이 '{args.index_dir}'에 인덱싱되었습니다.")
    print(f" - 인덱스 파일: {args.index_dir}/phishing_index.faiss")
    print(f" - 메타데이터: {args.index_dir}/metadata.jsonl")


if __name__ == "__main__":
    main()
