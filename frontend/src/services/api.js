export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const CLIENT_ID_KEY = "phishingClientId";

async function request(path, options, errorMessage) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);

  if (!response.ok) {
    throw new Error(`${errorMessage}: ${response.status}`);
  }

  return response.json();
}

export function getSavedClientId() {
  return localStorage.getItem(CLIENT_ID_KEY);
}

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

export async function createReport(analysisId, regenerate = false) {
  const clientId = await getClientId();

  return request(
    `/api/v1/analyses/${analysisId}/report${regenerate ? "?regenerate=true" : ""}`,
    {
      method: "POST",
      headers: {
        "X-Client-Id": clientId,
      },
    },
    "리포트 생성 실패"
  );
}

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
