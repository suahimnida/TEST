import "./DetectionMethods.css";

// 실제 판정 구조: 블랙리스트와 ML 모델이 최종 위험도를 정하고, 나머지는 판단 근거를 설명하는 참고 정보다
const methods = [
  {
    number: "01",
    title: "KISA 블랙리스트 (판정 반영)",
    description:
      "한국인터넷진흥원이 공개한 피싱 사이트 목록과 URL·도메인이 일치하면 피싱으로 확정합니다.",
    features: ["URL 일치", "도메인 일치", "KISA 2024 목록"],
  },
  {
    number: "02",
    title: "ML 모델 (판정 반영)",
    description:
      "URL 문자열의 문자 패턴(n-gram)으로 학습한 모델이 위험도를 계산합니다. 공식 도메인 허용 목록에 있는 사이트는 ML 점수만으로 피싱 판정을 내리지 않습니다.",
    features: ["문자 n-gram", "URL 원문 기반", "공식 도메인 허용 목록"],
  },
  {
    number: "03",
    title: "URL 구조 탐지 (참고)",
    description:
      "URL 문자열에서 의심 신호를 찾아 판단 근거로 보여 줍니다. 해킹당한 정상 사이트에 숨긴 피싱 페이지의 경로 형태도 확인합니다.",
    features: ["IP 주소·퓨니코드", "의심 키워드", "브랜드 사칭", "해킹 사이트 경로 패턴"],
  },
  {
    number: "04",
    title: "평판 신호 (참고)",
    description:
      "사이트에 접속하지 않고 공개된 등록 정보를 조회합니다. 외부 서비스에는 도메인 이름만 보냅니다.",
    features: ["도메인 등록일", "인증서 첫 발급일", "호스팅 정보"],
  },
  {
    number: "05",
    title: "유사 사례·AI 설명 (참고)",
    description:
      "특징이 비슷한 과거 사례를 찾고, AI가 판단 근거와 후속 조치를 설명합니다. AI는 최종 점수를 정하지 않습니다.",
    features: ["유사 사례 검색", "판단 근거 설명", "후속 조치 조사", "분석 리포트"],
  },
];

function DetectionMethods() {
  return (
    <section className="detection-methods-page">
      <div className="detection-methods-header">
        <p className="detection-eyebrow">
          DETECTION METHODS
        </p>

        <h2>탐지 방법</h2>

        <p className="detection-description">
          피싱 사이트 분석에 사용되는 주요 탐지 방법과
          분석 항목을 확인할 수 있습니다. 이 서비스는 분석할
          사이트에 접속하지 않으므로 페이지 내용(HTML, 텍스트,
          이미지)은 분석하지 않습니다.
        </p>
      </div>

      <div className="methods-list">
        {methods.map((method) => (
          <article
            className="method-card"
            key={method.number}
          >
            <div className="method-number">
              {method.number}
            </div>

            <div className="method-content">
              <h3>{method.title}</h3>

              <p>{method.description}</p>

              <div className="method-features">
                {method.features.map((feature) => (
                  <span key={feature}>
                    {feature}
                  </span>
                ))}
              </div>
            </div>
          </article>
        ))}
      </div>

      <div className="detection-flow">
        <div className="flow-header">
          <div>
            <p className="detection-eyebrow">
              ANALYSIS FLOW
            </p>

            <h3>분석 흐름</h3>
          </div>
        </div>

        <div className="flow-list">
          <div className="flow-item">
            <span>01</span>
            <strong>URL 입력</strong>
          </div>

          <span className="flow-arrow">→</span>

          <div className="flow-item">
            <span>02</span>
            <strong>블랙리스트·ML 판정</strong>
          </div>

          <span className="flow-arrow">→</span>

          <div className="flow-item">
            <span>03</span>
            <strong>근거 수집 (URL 구조·평판 신호)</strong>
          </div>

          <span className="flow-arrow">→</span>

          <div className="flow-item">
            <span>04</span>
            <strong>AI 설명·리포트</strong>
          </div>
        </div>
      </div>
    </section>
  );
}

export default DetectionMethods;