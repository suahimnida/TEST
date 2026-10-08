# 피싱 URL 분석 백엔드

URL을 받아 KISA 피싱사이트 목록 조회, RAG(유사 사례 검색 + Claude 판정)를 거쳐 결과를 반환하고 SQLite에 저장하는 FastAPI 서버입니다.

## 현재 상태

| 기능 | 상태 |
|---|---|
| KISA 블랙리스트 조회 | 동작 |
| SQLite 저장 / 조회 | 동작 |
| RAG | 연결됨. API 키와 벡터 스토어가 있어야 동작 (없으면 RAG만 꺼진 채 서버 실행) |
| ML 모델 | 연결됨 (`codes/ml_integration`). 모델 파일이 없으면 `model.status`가 `not_ready` |
| 최종 판정 (`verdict`, `risk_score` 등) | 연결됨 (`codes/ml_integration/risk_judge.py`). 블랙리스트 매치 시 즉시 피싱, 아니면 ML 점수로 판정 (RAG 점수는 아직 없음) |

## 실행 방법

Python 3.10 ~ 3.12가 필요합니다. ML 모델이 학습된 scikit-learn 1.3.2가 3.13 이상을 지원하지 않기 때문입니다.
(버전이 다른 scikit-learn을 쓰면 오류 없이 엉뚱한 점수가 나오니 `requirements.txt`의 고정 버전을 지켜주세요.)
아래 명령은 모두 `backend` 폴더에서 실행합니다.

### 1) 가상환경 만들기 (처음 한 번)

```bash
python -m venv .venv
```

### 2) 가상환경 켜기 (터미널을 열 때마다)

```powershell
# PowerShell
.venv\Scripts\activate
```

```bash
# Git Bash
source .venv/Scripts/activate
```

프롬프트 앞에 `(.venv)`가 보이면 켜진 것입니다.

### 3) 패키지 설치 (처음 한 번)

```bash
pip install -r requirements.txt
```

`sentence-transformers`가 PyTorch를 함께 설치해서 1GB 가까이 내려받습니다.

### 4) 서버 실행

```bash
uvicorn app.main:app --reload
```

`Application startup complete.`가 나오면 http://localhost:8000/docs 에서 API를 직접 호출해 볼 수 있습니다.

API 키나 벡터 스토어가 없으면 로그에 `RAG 비활성화: ...` 경고가 나오지만 정상입니다. 블랙리스트 조회와 저장은 그대로 동작합니다.

### 5) 테스트

```bash
pytest -q
```

테스트는 임시 DB를 사용하므로 실제 DB(`data/analyses.db`)에 영향을 주지 않습니다.

## RAG 켜기 (선택)

RAG까지 쓰려면 API 키와 벡터 스토어가 모두 필요합니다.

### API 키

`.env.example`을 복사해서 같은 폴더에 `.env`로 저장하고 키를 넣습니다.

```
ANTHROPIC_API_KEY=sk-ant-...
```

`.env`는 `.gitignore`에 들어 있어 커밋되지 않습니다. 키를 코드나 `.env.example`에 쓰지 마세요.

### 벡터 스토어

`codes/` 폴더에서 만듭니다. 가상환경을 켠 상태로 실행하세요. 전체 데이터(약 23만 건)는 오래 걸리므로, 확인용으로는 일부만 뽑아서 만드는 것을 권장합니다.

```bash
cd ../codes

# 데이터 압축 해제
python -m zipfile -e phiusiil+phishing+url+dataset.zip .

# 5천 건만 뽑기 (개수는 숫자만 바꾸면 됨)
python -c "import pandas as pd; pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv').sample(5000, random_state=42).to_csv('dataset_sample.csv', index=False)"

# 특징 추출 (데이터셋의 URL 열 이름이 대문자라 --url-col URL 필요)
python preprocess.py --input dataset_sample.csv --output features_sample.csv --url-col URL --invert-label

# 벡터 스토어 생성
python build_vector_store.py --input features_sample.csv --index-dir vector_store
```

`codes/vector_store/`가 생기면 서버를 재시작합니다. 로그에 `RAG 로드 완료`가 나오면 연결된 것입니다.

이 과정에서 생기는 CSV 파일과 `vector_store/`는 용량이 크니 커밋하지 마세요. 커밋할 때는 `git add .` 대신 `git add backend`처럼 폴더를 지정하는 것이 안전합니다.

## API

| 메서드 | 주소 | 설명 |
|---|---|---|
| GET | `/health` | 서버 동작 확인 |
| POST | `/api/v1/clients` | 브라우저 ID 발급 |
| POST | `/api/v1/analyses` | URL 분석 후 결과 저장 및 반환. 본문: `{"url": "...", "is_public": false}` |
| GET | `/api/v1/analyses/{analysis_id}` | 저장된 결과 조회. 비공개 결과는 만든 브라우저에서만 보이고, 아니면 404 |
| GET | `/api/v1/analyses?scope=mine` | 이 브라우저의 분석 기록 (헤더 필수) |
| GET | `/api/v1/analyses?scope=public` | 공개된 분석 기록 |

프론트는 처음 접속할 때 `/api/v1/clients`로 받은 ID를 로컬스토리지에 저장하고, 모든 요청에 `X-Client-Id` 헤더로 보냅니다. 로그인이 아니므로 브라우저 데이터를 지우면 기록을 다시 볼 수 없습니다. 공개 여부는 분석할 때 정하며 나중에 바꿀 수 없습니다(기본 비공개).

요청/응답의 자세한 형식은 서버 실행 후 `/docs`에서 확인할 수 있습니다.

## 환경변수

`.env`에 적거나 비워 두면 기본값을 사용합니다.

| 이름 | 기본값 | 설명 |
|---|---|---|
| `ANTHROPIC_API_KEY` | 없음 | Claude API 키. 없으면 RAG 꺼짐 |
| `RAG_INDEX_DIR` | `codes/vector_store` | 벡터 스토어 폴더 |
| `RAG_TOP_K` | `5` | 검색할 유사 사례 개수 |
| `ML_MODEL_DIR` | `codes/ml_integration/models` | ML 모델 파일 위치 |
| `BLACKLIST_DIR` | 프로젝트 루트 | `urls.json`, `hosts.json` 위치 |
| `DB_PATH` | `backend/data/analyses.db` | SQLite 파일 위치 |
| `CORS_ORIGINS` | `http://localhost:5173` | 요청을 허용할 프론트 주소 (쉼표로 여러 개) |

## 폴더 구조

```
backend/
├─ app/
│  ├─ main.py            # 서버 진입점, API 정의
│  ├─ schemas.py         # 요청/응답 형식
│  ├─ db.py              # SQLite 저장/조회
│  └─ services/
│     ├─ blacklist.py    # KISA 블랙리스트 조회
│     ├─ model.py        # ML 모델 (codes/ml_integration 호출)
│     ├─ rag.py          # RAG: 유사 사례 검색 + Claude 판정
│     └─ verdict.py      # 최종 판정 (codes/ml_integration/risk_judge.py 호출)
├─ tests/
├─ .env.example
└─ requirements.txt
```

## 문제 해결

- **`uvicorn`이나 `fastapi`를 찾을 수 없음**: 가상환경이 켜지지 않았습니다. 2)를 다시 하세요.
- **PowerShell에서 "스크립트를 실행할 수 없습니다"**: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`를 한 번 실행한 뒤 다시 켜세요.
- **`No module named 'app'`**: `backend` 폴더가 아닌 곳에서 실행했습니다.
- **포트 8000 사용 중**: 이미 켜진 서버를 끄거나 `--port 8001`을 붙여 실행하세요.