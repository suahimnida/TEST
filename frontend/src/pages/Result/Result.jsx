import "./Result.css";

const detectionLabels = {
  url: {
    title: "URL 구조",
    description: "URL 구조와 문자열 패턴 분석",
  },
  url_stats: {
    title: "URL 통계",
    description: "URL 길이, 엔트로피 및 n-gram 패턴 분석",
  },
  domain: {
    title: "도메인 분석",
    description: "도메인, 인증서 및 리디렉션 분석",
  },
  html: {
    title: "HTML 분석",
    description: "HTML 구조 및 의심스러운 요소 분석",
  },
  image: {
    title: "페이지 콘텐츠",
    description: "텍스트 및 이미지 콘텐츠 분석",
  },
};

const detectionStatusLabels = {
  suspicious: "의심됨",
  normal: "정상",
  not_analyzed: "분석되지 않음",
};

const riskLevelLabels = {
  safe: "안전",
  caution: "주의",
  warning: "경고",
  danger: "위험",
};

const verdictLabels = {
  phishing: "피싱",
  suspicious: "의심",
  normal: "정상",
};

const modelStatusLabels = {
  ready: "정상 작동",
  not_ready: "사용할 수 없음",
};

const matchTypeLabels = {
  none: "일치하지 않음",
  exact: "정확히 일치",
  host: "도메인 일치",
};

function Result({ url, result }) {
  if (!result) {
    return (
      <section className="result-page">
        <div className="result-header">
          <p className="eyebrow">보안 분석 결과</p>

          <h2>분석 결과를 불러올 수 없습니다.</h2>

          <p className="result-description">
            분석 결과가 존재하지 않습니다.
          </p>
        </div>
      </section>
    );
  }

  const data = result;

  const detectionEntries = Object.entries(
    data.detections || {}
  ).filter(([, value]) => value !== null);

  const suspiciousDetectionCount =
    detectionEntries.filter(
      ([, value]) => value?.status === "suspicious"
    ).length;

  const riskLevel =
    data.risk_level || "caution";

  const verdict =
    data.verdict || "suspicious";

  const riskScore =
    data.risk_score !== null &&
    data.risk_score !== undefined
      ? Number(data.risk_score)
      : null;

  // 백엔드는 신뢰도를 0~1 비율로 보낸다 (예: 0.91). 화면에는 퍼센트로 표시한다
  const confidence =
    data.confidence !== null &&
    data.confidence !== undefined
      ? Number(data.confidence) * 100
      : null;

  return (
    <section className="result-page">
      {/* Header */}
      <div className="result-header">
        <p className="eyebrow">보안 분석 결과</p>

        <h2>분석 결과</h2>

        <p className="result-description">
          입력한 웹사이트의 보안 분석 결과입니다.
        </p>
      </div>

      {/* Target */}
      <div className="result-target">
        <div>
          <p className="result-target-label">
            분석 대상 URL
          </p>

          <p className="result-target-url">
            {data.url || url || "-"}
          </p>
        </div>

        <span className="result-completed">
          {data.status === "completed"
            ? "분석 완료"
            : data.status || "분석 상태 확인 필요"}
        </span>
      </div>

      {/* Overall Risk */}
      <div className={`risk-card ${riskLevel}`}>
        <div className="risk-score">
          <div>
            <span className="score-number">
              {riskScore !== null
                ? riskScore.toFixed(1)
                : "-"}
            </span>

            <span className="score-unit">
              / 100
            </span>
          </div>

          <span className="risk-level">
            {riskLevelLabels[riskLevel] ||
              riskLevel}
          </span>
        </div>

        <div className="risk-info">
          <p className="risk-label">
            최종 위험도
          </p>

          <h3>
            {verdictLabels[verdict] ||
              verdict} 
          </h3>

          <p>
            {confidence !== null
              ? `판정 신뢰도: ${Math.round(confidence)}%`
              : "판정 신뢰도 정보가 없습니다."}
          </p>

          <p>
            최종 위험도는 URL 분석 결과와 ML 모델 분석 결과를
            종합하여 판단됩니다.
          </p>
        </div>
      </div>

      {/* Blacklist */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>블랙리스트 조회</p>
          </div>

          <span>KISA</span>
        </div>

        <div className="assistant-card">
          <div className="finding">
            <div
              className={`finding-icon ${
                data.blacklist?.matched
                  ? "danger"
                  : "normal"
              }`}
            >
              {data.blacklist?.matched
                ? "!"
                : "✓"}
            </div>

            <div>
              <h4>
                {data.blacklist?.matched
                  ? "블랙리스트 일치"
                  : "블랙리스트 미일치"}
              </h4>

              <p>
                {data.blacklist?.matched
                  ? "KISA 피싱 사이트 데이터에서 일치하는 정보가 확인되었습니다."
                  : "KISA 피싱 사이트 데이터에서 일치하는 정보가 확인되지 않았습니다."}
              </p>

              <p>
                일치 유형:{" "}
                {matchTypeLabels[
                  data.blacklist?.match_type
                ] ||
                  data.blacklist?.match_type ||
                  "-"}
              </p>

              <p>
                출처:{" "}
                {data.blacklist?.source || "-"}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Detection */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>탐지 결과</p>
          </div>

          <span>
            {detectionEntries.length}개 항목
            {suspiciousDetectionCount > 0
              ? ` 중 의심 ${suspiciousDetectionCount}개`
              : ""}
          </span>
        </div>

        <div className="detection-list">
          {detectionEntries.length > 0 ? (
            detectionEntries.map(
              ([key, detection]) => {
                const info =
                  detectionLabels[key];

                /*
                 * detections의 실제 값 구조가
                 * 아직 항목별로 확정되지 않았기 때문에
                 * 문자열/객체 모두 안전하게 표시합니다.
                 */
                let status = null;
                let reasons = [];
                let notes = [];

                if (
                  typeof detection === "string"
                ) {
                  status = detection;
                } else if (
                  detection &&
                  typeof detection === "object"
                ) {
                  status =
                    detection.status ||
                    detection.label ||
                    null;
                  reasons = Array.isArray(detection.reasons)
                    ? detection.reasons
                    : [];
                  notes = Array.isArray(detection.notes)
                    ? detection.notes
                    : [];
                }

                return (
                  <div
                    className={`detection-row ${
                      status === "suspicious"
                        ? "suspicious"
                        : status === "normal"
                        ? "normal"
                        : status === "not_analyzed"
                        ? "not-analyzed"
                        : ""
                    }`}
                    key={key}
                  >
                    <div>
                      <h4>
                        {info?.title || key}
                      </h4>

                      <p>
                        {info?.description ||
                          "분석 결과"}
                      </p>

                      {reasons.length + notes.length > 0 && (
                        <ul className="detection-findings">
                          {reasons.map((text) => (
                            <li
                              className="detection-reason"
                              key={`reason-${text}`}
                            >
                              {text}
                            </li>
                          ))}

                          {notes.map((text) => (
                            <li
                              className="detection-note"
                              key={`note-${text}`}
                            >
                              {text}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    <span>
                      {detectionStatusLabels[
                        status
                      ] ||
                        status ||
                        "분석 완료"}
                    </span>
                  </div>
                );
              }
            )
          ) : (
            <div className="detection-row">
              <div>
                <h4>탐지 데이터 없음</h4>

                <p>
                  현재 제공된 탐지 항목이 없습니다.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Similar Cases */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>유사 피싱 사례</p>
          </div>

          <span>RAG</span>
        </div>

        <div className="assistant-card">
          {data.similar_cases?.length > 0 ? (
            data.similar_cases.map(
              (item, index) => (
                <div
                  className="finding"
                  key={`${item.url}-${index}`}
                >
                  <div className="finding-icon danger">
                    !
                  </div>

                  <div>
                    <h4>유사 사이트</h4>

                    <p>{item.url}</p>

                    <p>
                      피싱 여부:{" "}
                      {item.label === 1
                        ? "피싱"
                        : "정상"}
                    </p>

                    <p>
                      유사도:{" "}
                      {typeof item.similarity ===
                      "number"
                        ? `${Math.round(
                            item.similarity * 100
                          )}%`
                        : "-"}
                    </p>
                  </div>
                </div>
              )
            )
          ) : (
            <p>
              유사 피싱 사례가 없습니다.
            </p>
          )}
        </div>
      </div>

      {/* RAG Evidence */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>보안 근거</p>
          </div>

          <span>RAG</span>
        </div>

        <div className="assistant-card">
          {data.rag?.matched ? (
            <>
              <div className="finding">
                <div className="finding-icon normal">
                  R
                </div>

                <div>
                  <h4>관련 보안 자료 확인</h4>

                  <p>
                    {data.rag.evidence ||
                      "관련 보안 문서의 근거가 확인되었습니다."}
                  </p>
                </div>
              </div>

              {data.rag.source?.length > 0 && (
                <div className="finding">
                  <div className="finding-icon normal">
                    ✓
                  </div>

                  <div>
                    <h4>참고 자료</h4>

                    {data.rag.source.map(
                      (source, index) => (
                        <p key={index}>
                          {source}
                        </p>
                      )
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <p>
              관련 RAG 근거가 없습니다.
            </p>
          )}
        </div>
      </div>

      {/* AI Analysis */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>AI 분석</p>
          </div>

          <span>AI Agent</span>
        </div>

        <div className="ai-analysis-card">
          <div className="ai-badge">
            AI
          </div>

          <div>
            <h3>분석 결과 설명</h3>

            <p className="ai-summary">
              {data.ai_analysis?.summary ||
                "AI 분석 설명이 아직 제공되지 않았습니다."}
            </p>

            {data.ai_analysis?.reasons?.length >
              0 && (
              <div className="ai-reasons">
                {data.ai_analysis.reasons.map(
                  (reason, index) => (
                    <div key={index}>
                      <span>✓</span>

                      <p>{reason}</p>
                    </div>
                  )
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Model */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>ML 모델</p>
          </div>

          <span>Machine Learning</span>
        </div>

        <div className="assistant-card">
          <div className="finding">
            <div
              className={`finding-icon ${
                data.model?.status === "ready"
                  ? "normal"
                  : "danger"
              }`}
            >
              AI
            </div>

            <div>
              <h4>모델 상태</h4>

              <p>
                {modelStatusLabels[
                  data.model?.status
                ] ||
                  data.model?.status ||
                  "확인되지 않음"}
              </p>
            </div>
          </div>

          <div className="finding">
            <div className="finding-icon normal">
              ✓
            </div>

            <div>
              <h4>모델 위험도 점수</h4>

              <p>
                {data.model?.risk_score !==
                  null &&
                data.model?.risk_score !==
                  undefined
                  ? `${data.model.risk_score} / 100`
                  : "아직 산출되지 않았습니다."}
              </p>
            </div>
          </div>

          <div className="finding">
            <div className="finding-icon normal">
              ✓
            </div>

            <div>
              <h4>모델 판정</h4>

              <p>
                {data.model?.label ===
                "phishing"
                  ? "피싱"
                  : data.model?.label ===
                    "normal"
                  ? "정상"
                  : "아직 판정되지 않았습니다."}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Extracted Features */}
      {data.extracted_features &&
        Object.keys(data.extracted_features)
          .length > 0 && (
          <div className="result-section">
            <div className="section-heading">
              <div>
                <p>추출된 특징</p>
              </div>

              <span>Features</span>
            </div>

            <div className="assistant-card">
              {Object.entries(
                data.extracted_features
              ).map(([key, value]) => (
                <div
                  className="finding"
                  key={key}
                >
                  <div className="finding-icon normal">
                    ✓
                  </div>

                  <div>
                    <h4>{key}</h4>

                    <p>
                      {typeof value ===
                      "object"
                        ? JSON.stringify(value)
                        : String(value)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      {/* Report */}
      <div className="report-card">
        <div>
          <p className="report-label">
            자동 리포트
          </p>

          <h3>AI 분석 리포트 생성</h3>

          <p>
            현재 분석 결과를 바탕으로 보안 분석
            리포트를 생성합니다.
          </p>
        </div>

        <button className="report-button">
          리포트 생성
          <span>→</span>
        </button>
      </div>
    </section>
  );
}

export default Result;