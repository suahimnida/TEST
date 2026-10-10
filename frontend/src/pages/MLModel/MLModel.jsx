import "./MLModel.css";

// 서비스 모델 v2 (backend/ml_integration/models/url_model_v2_report.json)
const features = [
  "문자 n-gram (3~5글자)",
  "URL 원문 그대로 (대소문자·특수문자 유지)",
  "로지스틱 회귀 분류",
  "검증 세트로 정한 판정 기준점",
];

// 학습에서 일부러 뺀 것과 이유
const excluded = [
  {
    title: "https·www 유무",
    reason:
      "기존 학습 데이터의 정상 URL이 모두 https://www. 형태라, 넣으면 모델이 형태만 보고 판단하는 지름길을 배웁니다.",
  },
];

function MLModel() {
  return (
    <section className="ml-model-page">
      <div className="ml-model-header">
        <p className="ml-model-eyebrow">ML MODEL</p>

        <h2>ML 모델</h2>

        <p className="ml-model-description">
          URL 문자열만 보고 피싱 가능성을 계산하는 머신러닝 모델입니다.
        </p>
      </div>

      <div className="ml-overview">
        <div className="ml-overview-content">
          <span className="ml-section-number">01</span>

          <div>
            <h3>URL 기반 피싱 탐지</h3>

            <p>
              입력된 URL 원문에서 3~5글자 문자 조합(n-gram)을
              뽑아 정상·피싱 URL로 학습한 모델이 위험도를
              계산합니다. 학습에 없던 데이터로 평가했을 때
              정상 URL을 피싱으로 잘못 판정하는 비율은 34.2%,
              피싱을 놓치는 비율은 13.3%입니다.
            </p>
          </div>
        </div>
      </div>

      <div className="ml-section">
        <div className="ml-section-header">
          <div>
            <p className="ml-model-eyebrow">FEATURES</p>
            <h3>사용 특징</h3>
          </div>

          <span>URL Analysis</span>
        </div>

        <div className="ml-feature-grid">
          {features.map((feature, index) => (
            <div className="ml-feature-card" key={feature}>
              <span>
                {String(index + 1).padStart(2, "0")}
              </span>
              <strong>{feature}</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="ml-section">
        <div className="ml-section-header">
          <div>
            <p className="ml-model-eyebrow">NOT USED</p>
            <h3>학습에서 뺀 것</h3>
          </div>
        </div>

        <div className="ml-feature-grid">
          {excluded.map((item) => (
            <div className="ml-feature-card" key={item.title}>
              <strong>{item.title}</strong>
              <p>{item.reason}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="ml-section">
        <div className="ml-section-header">
          <div>
            <p className="ml-model-eyebrow">ANALYSIS FLOW</p>
            <h3>분석 과정</h3>
          </div>
        </div>

        <div className="ml-flow">
          <div className="ml-flow-item">
            <span>01</span>
            <strong>URL 입력</strong>
            <p>분석할 웹사이트 URL</p>
          </div>

          <div className="ml-flow-arrow">→</div>

          <div className="ml-flow-item">
            <span>02</span>
            <strong>문자 조합 추출</strong>
            <p>URL 원문의 3~5글자 n-gram</p>
          </div>

          <div className="ml-flow-arrow">→</div>

          <div className="ml-flow-item">
            <span>03</span>
            <strong>ML 분류</strong>
            <p>정상 / 피싱 분류</p>
          </div>

          <div className="ml-flow-arrow">→</div>

          <div className="ml-flow-item">
            <span>04</span>
            <strong>기준점 보정</strong>
            <p>의심 30점 · 피싱 60점</p>
          </div>
        </div>
      </div>

      <div className="ml-info-grid">
        <div className="ml-info-card">
          <span>DATASET</span>
          <strong>PhiUSIIL + 공개 URL + KISA</strong>
          <p>형태 편향을 고친 정상·피싱 URL 약 19만 건</p>
        </div>

        <div className="ml-info-card">
          <span>INPUT</span>
          <strong>URL 원문</strong>
          <p>입력한 URL 문자열</p>
        </div>

        <div className="ml-info-card">
          <span>OUTPUT</span>
          <strong>Normal / Phishing</strong>
          <p>피싱 가능성 분류 결과</p>
        </div>
      </div>
    </section>
  );
}

export default MLModel;

