import ShareControls from "../../components/Share/ShareControls";
import GroundedAnalysis from "../../components/Grounded/GroundedAnalysis";
import ModelExplanation from "../../components/Explanation/ModelExplanation";
import ReportSection from "../../components/Report/ReportSection";
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
    description: "최상위 도메인, 브랜드 사칭, 서브도메인 구조 분석",
  },
  reputation: {
    title: "평판 신호",
    description: "도메인 등록일, 인증서 첫 발급일, 호스팅 정보 (참고 근거)",
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

function Result({ url, result, shareToken, onResultChange }) {
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

  // 화면에 이름이 정해진 탐지 항목만 보여 준다
  const detectionEntries = Object.entries(
    data.detections || {}
  ).filter(([key, value]) => value !== null && key in detectionLabels);

  const similarCases = Array.isArray(data.similar_cases)
    ? data.similar_cases
    : [];
  const similarPhishingCount = similarCases.filter(
    (item) => item.label === 1
  ).length;

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
          입력한 URL의 보안 분석 결과입니다.
        </p>
      </div>

      {/* 분석 범위: 사이트에 접속하지 않았다는 점을 결과보다 먼저 밝힌다 */}
      {/* 공개 범위와 "링크가 있는 사람은 볼 수 있음" */}
      {data.viewer && <ShareControls result={data} onChange={onResultChange} />}

      <div className="analysis-scope">
        <strong>분석 범위</strong>
        <p>
          URL 문자열과 공개된 등록 정보(KISA 블랙리스트, 도메인 등록일,
          인증서 기록, 호스팅 정보)만 확인했습니다. 이 사이트에는 접속하지
          않았습니다.
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

      {/* 판단 근거 수치: 모델이 URL의 어느 부분 때문에 위험하다고 봤는지 */}
      <ModelExplanation
        explanation={data.explanation}
        allowlisted={Boolean(data.allowlist?.matched)}
      />

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

              {data.allowlist?.matched && (
                <p>
                  공식 도메인 허용 목록: {data.allowlist.domain} (ML 점수만으로
                  피싱 판정을 내리지 않음)
                </p>
              )}
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
            <p>유사 사례</p>
          </div>

          <span>
            {similarCases.length > 0
              ? `피싱 ${similarPhishingCount}건 · 정상 ${
                  similarCases.length - similarPhishingCount
                }건`
              : "RAG"}
          </span>
        </div>

        <div className="assistant-card">
          {similarCases.length > 0 ? (
            similarCases.map(
              (item, index) => (
                <div
                  className="finding"
                  key={`${item.url}-${index}`}
                >
                  <div
                    className={`finding-icon ${
                      item.label === 1 ? "danger" : "normal"
                    }`}
                  >
                    {item.label === 1 ? "!" : "✓"}
                  </div>

                  <div>
                    <h4>
                      {item.label === 1
                        ? "유사한 피싱 사이트"
                        : "유사한 정상 사이트"}
                    </h4>

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
              유사 사례가 없습니다.
            </p>
          )}
        </div>
      </div>

      {/* ② RAG 대응 가이드 + ③ LLM 출처 있는 설명 (① ML 근거는 위 "판단 근거 수치") */}
      <GroundedAnalysis ai={data.ai_analysis} rag={data.rag} />

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

      {/* Report: 리포트 생성, PDF 보기·저장. 다른 분석 결과로 바뀌면 key로 상태를 초기화한다 */}
      {data.id && <ReportSection key={data.id} analysisId={data.id} shareToken={shareToken} />}
    </section>
  );
}

export default Result;