import "./GroundedAnalysis.css";

// 설명 문장 속 [E1], [G2] 번호를 눈에 띄게 표시한다
function withCitations(text) {
  return text.split(/(\[[EG]\d+\])/g).map((part, i) => {
    const match = part.match(/^\[([EG])(\d+)\]$/);
    if (!match) return <span key={i}>{part}</span>;
    return (
      <a key={i} href={`#cite-${match[1]}${match[2]}`} className={`cite cite-${match[1]}`}>
        {match[1]}
        {match[2]}
      </a>
    );
  });
}

function GroundedAnalysis({ ai, rag }) {
  const evidence = ai?.evidence || [];
  const guides = ai?.guides || [];
  const legacySources = guides.length === 0 ? rag?.source || [] : [];

  return (
    <>
      {/* ② RAG: 근거에 맞는 공식 기관 대응 가이드 */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>대응 가이드</p>
          </div>
          <span>RAG · 공식 기관 안내</span>
        </div>

        <div className="grounded-card">
          {guides.length > 0 ? (
            <>
              <p className="grounded-hint">
                아래 분석 근거에서 상황을 찾아 공식 기관 안내 중 맞는 가이드를 골랐어요.
                내용은 서비스가 요약한 것이니 원문은 출처 링크에서 확인하세요.
              </p>
              <ul className="guide-list">
                {guides.map((g) => (
                  <li key={g.id} id={`cite-${g.id}`}>
                    <span className="cite cite-G">{g.id}</span>
                    <div>
                      <h4>{g.title}</h4>
                      <p>{g.text}</p>
                      <div className="guide-meta">
                        <a href={g.url} target="_blank" rel="noopener noreferrer">
                          출처: {g.source} ↗
                        </a>
                        {g.matched?.length > 0 && <span>이 가이드를 고른 이유: {g.matched.join(", ")}</span>}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          ) : legacySources.length > 0 ? (
            legacySources.map((s) => <p key={s}>{s}</p>)
          ) : (
            <p className="grounded-hint">찾은 대응 가이드가 없습니다.</p>
          )}
        </div>
      </div>

      {/* ③ LLM: ML 근거[E]와 가이드[G]를 합쳐 출처가 있는 설명 */}
      <div className="result-section">
        <div className="section-heading">
          <div>
            <p>AI 분석</p>
          </div>
          <span>
            {ai?.written_by === "template" ? "기본 템플릿" : ai?.written_by || "AI"} · 출처 표시
          </span>
        </div>

        <div className="grounded-card">
          <p className="grounded-summary">
            {ai?.summary ? withCitations(ai.summary) : "AI 분석 설명이 아직 제공되지 않았습니다."}
          </p>

          {evidence.length > 0 && (
            <>
              <p className="grounded-hint">
                설명의 <span className="cite cite-E">E</span> 번호는 아래 분석 근거,{" "}
                <span className="cite cite-G">G</span> 번호는 위 대응 가이드를 가리켜요. AI는 위험도를
                정하지 않고, 이 근거와 가이드만으로 설명을 써요.
              </p>
              <ul className="evidence-list">
                {evidence.map((e) => (
                  <li key={e.id} id={`cite-${e.id}`}>
                    <span className="cite cite-E">{e.id}</span>
                    <span className={`evidence-badge ${e.used_in_verdict ? "used" : ""}`}>
                      {e.used_in_verdict ? "판정 반영" : "참고"}
                    </span>
                    <div>
                      <strong>{e.source}</strong>
                      <p>{e.text}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </>
  );
}

export default GroundedAnalysis;
