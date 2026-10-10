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
// ownerName·ownerSecret: 공개 분석에 표시할 성명(서버가 가려서 저장)과 삭제 때 본인 확인용 식별 암호
export async function analyzeUrl(url, isPublic = false, ownerName = null, ownerSecret = null) {
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
        owner_name: ownerName || undefined,
        owner_secret: ownerSecret || undefined,
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

// 공유 링크로 연 결과는 토큰을 함께 보내야 리포트를 볼 수 있다
function shareQuery(shareToken) {
  return shareToken ? `?share=${encodeURIComponent(shareToken)}` : "";
}

// 분석 리포트 생성. 분석 1건당 한 번만 만들고, 이미 있으면 서버가 저장된 것을 돌려준다.
export async function createReport(analysisId, shareToken = null) {
  const clientId = await getClientId();

  return request(
    `/api/v1/analyses/${analysisId}/report${shareQuery(shareToken)}`,
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
export async function fetchReportPdf(analysisId, shareToken = null) {
  const clientId = await getClientId();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/analyses/${analysisId}/report.pdf${shareQuery(shareToken)}`,
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

// 다른 사용자가 공개한 분석 기록 목록
export async function listPublicAnalyses() {
  const data = await request("/api/v1/analyses?scope=public", {}, "공개 분석 조회 실패");
  return Array.isArray(data.items) ? data.items : [];
}

// 내 분석 결과의 공개 여부 바꾸기
export async function setVisibility(analysisId, isPublic) {
  const clientId = await getClientId();

  return request(
    `/api/v1/analyses/${analysisId}/visibility`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-Client-Id": clientId },
      body: JSON.stringify({ is_public: isPublic }),
    },
    "공개 범위 변경 실패"
  );
}

// "링크가 있는 사람은 볼 수 있음" 켜기. 이미 있으면 같은 토큰을 돌려준다
export async function createShareLink(analysisId) {
  const clientId = await getClientId();

  const data = await request(
    `/api/v1/analyses/${analysisId}/share`,
    { method: "POST", headers: { "X-Client-Id": clientId } },
    "공유 링크 생성 실패"
  );
  return data.token;
}

// 공유 중지. 이미 보낸 링크는 더 이상 열리지 않는다
export async function revokeShareLink(analysisId) {
  const clientId = await getClientId();

  await request(
    `/api/v1/analyses/${analysisId}/share`,
    { method: "DELETE", headers: { "X-Client-Id": clientId } },
    "공유 중지 실패"
  );
}

// 공유 링크로 결과 열기 (브라우저 ID 없이도 열린다)
export async function getSharedAnalysis(token) {
  return request(`/api/v1/shared/${encodeURIComponent(token)}`, {}, "공유된 결과 조회 실패");
}

// 공유 링크 주소
export function shareUrl(token) {
  return `${window.location.origin}/?share=${encodeURIComponent(token)}`;
}

// 분석 결과 삭제 1단계: 분석할 때 입력한 성명과 사용자 식별 암호 확인
export async function verifyOwner(analysisId, name, secret) {
  const response = await fetch(`${API_BASE_URL}/api/v1/analyses/${analysisId}/verify-owner`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, secret }),
  });
  if (!response.ok) {
    const error = new Error(`본인 확인 실패: ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

// 분석 결과 삭제 2단계: 서버가 성명·식별 암호와 확인 문구를 다시 검사한 뒤 삭제한다
export async function deleteAnalysis(analysisId, name, secret, confirmText) {
  const response = await fetch(`${API_BASE_URL}/api/v1/analyses/${analysisId}/delete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, secret, confirm_text: confirmText }),
  });
  if (!response.ok) {
    const error = new Error(`분석 결과 삭제 실패: ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}
