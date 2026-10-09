// 백엔드 API 호출은 모두 이 파일에서 한다.
// 페이지 컴포넌트는 fetch를 직접 쓰지 않고 아래 함수만 불러 쓴다.

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const CLIENT_ID_KEY = "phishingClientId";

// 공통 요청 함수: 응답이 실패면 에러를 던지고, 성공이면 JSON을 돌려준다.
async function request(path, options, errorMessage) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);

  if (!response.ok) {
    throw new Error(`${errorMessage}: ${response.status}`);
  }

  return response.json();
}

// 이 브라우저에 저장된 ID만 확인한다. 없으면 null (새로 발급하지 않음).
export function getSavedClientId() {
  return localStorage.getItem(CLIENT_ID_KEY);
}

// 저장된 ID가 없으면 백엔드에서 새로 발급받아 저장한다.
export async function getClientId() {
  const savedClientId = getSavedClientId();

  if (savedClientId) {
    return savedClientId;
  }

  const data = await request(
    "/api/v1/clients",
    { method: "POST" },
    "클라이언트 ID 발급 실패"
  );

  localStorage.setItem(CLIENT_ID_KEY, data.client_id);

  return data.client_id;
}

// URL 분석 요청
export async function analyzeUrl(url, isPublic = false) {
  const clientId = await getClientId();

  return request(
    "/api/v1/analyses",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Id": clientId,
      },
      body: JSON.stringify({
        url,
        is_public: isPublic,
      }),
    },
    "URL 분석 요청 실패"
  );
}

// 이 브라우저의 분석 기록 목록. 백엔드 응답 { items: [...] }에서 배열만 돌려준다.
export async function listMyAnalyses() {
  const clientId = await getClientId();

  const data = await request(
    "/api/v1/analyses?scope=mine",
    {
      headers: {
        "X-Client-Id": clientId,
      },
    },
    "분석 기록 조회 실패"
  );

  return Array.isArray(data.items) ? data.items : [];
}

// 분석 결과 하나 조회
export async function getAnalysis(analysisId) {
  const clientId = await getClientId();

  return request(
    `/api/v1/analyses/${analysisId}`,
    {
      headers: {
        "X-Client-Id": clientId,
      },
    },
    "분석 결과 조회 실패"
  );
}

// 분석 리포트 생성. 분석 1건당 한 번만 만들고, 이미 있으면 서버가 저장된 것을 돌려준다.
export async function createReport(analysisId) {
  const clientId = await getClientId();

  return request(
    `/api/v1/analyses/${analysisId}/report`,
    {
      method: "POST",
      headers: {
        "X-Client-Id": clientId,
      },
    },
    "리포트 생성 실패"
  );
}

// 리포트 PDF 파일(Blob)
export async function fetchReportPdf(analysisId) {
  const clientId = await getClientId();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/analyses/${analysisId}/report.pdf`,
    {
      headers: {
        "X-Client-Id": clientId,
      },
    }
  );

  if (!response.ok) {
    throw new Error(`PDF 생성 실패: ${response.status}`);
  }

  return response.blob();
}

export function reportFileName(analysisId) {
  return `phishing-report-${String(analysisId).slice(0, 8)}.pdf`;
}
