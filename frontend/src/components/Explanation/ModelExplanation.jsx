import "./ModelExplanation.css";

// 글자별 기여도를 같은 색 구간끼리 묶어 URL 위에 칠한다
function toRuns(url, scores) {
  const max = Math.max(...scores.map((s) => Math.abs(s)), 1e-9);
  const level = (s) => {
    const ratio = Math.abs(s) / max;
    if (ratio < 0.12) return 0;
    const strength = ratio < 0.35 ? 1 : ratio < 0.65 ? 2 : 3;
    return s > 0 ? strength : -strength;
  };

  const runs = [];
  for (let i = 0; i < url.length; i += 1) {
    const lv = level(scores[i] ?? 0);
    const last = runs[runs.length - 1];
    if (last && last.level === lv) {
      last.text += url[i];
      last.sum += scores[i] ?? 0;
    } else {
      runs.push({ text: url[i], level: lv, sum: scores[i] ?? 0 });
    }
  }
  return runs;
}

function signed(value) {
  return `${value > 0 ? "+" : ""}${value.toFixed(2)}`;
}

function ModelExplanation({ explanation, allowlisted }) {
  if (!explanation) {
    return null;
  }

  const model = explanation.model;
  const reference = explanation.reference || [];
  const parts = model ? model.parts.filter((p) => p.text || p.contribution) : [];
  const maxPart = Math.max(...parts.map((p) => Math.abs(p.contribution)), 1e-9);

  return (
    <div className="result-section">
      <div className="section-heading">
        <div>
          <p>판단 근거 수치</p>
        </div>
        <span>Explanation</span>
      </div>

      <div className="explain-card">
        {model ? (
          <>
            <div className="explain-block">
              <h4>URL에서 모델이 주목한 부분</h4>
              <p className="explain-hint">
                빨간색은 피싱 쪽, 초록색은 정상 쪽으로 점수를 민 글자예요.
                색이 진할수록 영향이 커요.
              </p>
              <div className="explain-url" aria-label="URL 글자별 위험 기여도">
                {toRuns(model.url, model.char_scores).map((run, i) => (
                  <span
                    key={i}
                    className={`heat heat-${run.level < 0 ? "n" : "p"}${Math.abs(run.level)}`}
                    title={`기여도 ${signed(run.sum)}`}
                  >
                    {run.text}
                  </span>
                ))}
              </div>
            </div>

            <div className="explain-block">
              <h4>URL 부분별 위험 기여도</h4>
              <p className="explain-hint">
                모델 점수(로그 오즈 {signed(model.logit)}, 확률{" "}
                {(model.probability * 100).toFixed(1)}%)를 URL 부분별로 나눈 값이에요.
                기본값 {signed(model.intercept)}에 아래 값을 모두 더하면 모델 점수와 같아요.
              </p>
              <ul className="explain-parts">
                {parts.map((p) => (
                  <li key={`${p.part}-${p.text}`}>
                    <span className="explain-part-name">{p.part}</span>
                    <code className="explain-part-text">{p.text || "-"}</code>
                    <span className="explain-bar">
                      <span
                        className={p.contribution >= 0 ? "bar-risk" : "bar-safe"}
                        style={{ width: `${(Math.abs(p.contribution) / maxPart) * 100}%` }}
                      />
                    </span>
                    <strong className={p.contribution >= 0 ? "risk" : "safe"}>
                      {signed(p.contribution)}
                    </strong>
                  </li>
                ))}
              </ul>
            </div>

            <div className="explain-block">
              <h4>영향이 큰 문자 조합</h4>
              <div className="explain-grams">
                {model.top_risky.map((g) => (
                  <span className="gram risk" key={`r-${g.text}`}>
                    <code>{g.text}</code> {signed(g.contribution)}
                  </span>
                ))}
                {model.top_safe.map((g) => (
                  <span className="gram safe" key={`s-${g.text}`}>
                    <code>{g.text}</code> {signed(g.contribution)}
                  </span>
                ))}
              </div>
            </div>

            {allowlisted && (
              <p className="explain-note">
                공식 도메인 허용 목록에 있는 사이트라 최종 위험도는 이 모델 점수와 관계없이 낮게
                제한됐어요. 위 수치는 모델이 URL 문자열만 보고 어떻게 판단했는지 보여 줘요.
              </p>
            )}
          </>
        ) : (
          <p className="explain-note">
            KISA 블랙리스트에서 확인돼 ML 모델을 거치지 않았어요. 아래 참고 지표만 보여 드려요.
          </p>
        )}

        {reference.length > 0 && (
          <div className="explain-block">
            <h4>정상 데이터 대비 위치 (참고 지표)</h4>
            <p className="explain-hint">
              학습에 쓴 정상 URL 10만 건과 비교한 값이에요. 이 지표들은 모델 입력이 아니라
              이해를 돕는 참고 정보이고, 정상·피싱의 중앙값이 비슷하게 맞춰진 데이터라
              평범한 피싱보다는 눈에 띄게 튀는 URL을 찾는 데 의미가 있어요.
            </p>
            <div className="explain-table-wrap">
              <table className="explain-table">
                <thead>
                  <tr>
                    <th>지표</th>
                    <th>이 URL</th>
                    <th>정상 중앙값</th>
                    <th>정상 상위 95%</th>
                    <th>정상 URL 중 위치</th>
                  </tr>
                </thead>
                <tbody>
                  {reference.map((r) => (
                    <tr key={r.key} className={r.outside_normal ? "outside" : ""}>
                      <td>{r.name}</td>
                      <td>
                        <strong>
                          {r.value}
                          {r.unit}
                        </strong>
                      </td>
                      <td>
                        {r.normal_median}
                        {r.unit}
                      </td>
                      <td>
                        {r.normal_p95}
                        {r.unit}
                      </td>
                      <td>
                        {r.outside_normal ? (
                          <span className="badge-outside">
                            정상 URL의 {r.normal_percentile}%보다 큼 · 정상 범위 밖
                          </span>
                        ) : r.value > r.normal_median ? (
                          `정상 URL의 ${r.normal_percentile}%보다 큼`
                        ) : (
                          "정상 중앙값 이하"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ModelExplanation;
