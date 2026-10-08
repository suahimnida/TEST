import { useEffect, useState } from "react";
import { getSavedClientId, listMyAnalyses } from "../../services/api";
import "./Home.css";

function Home({ onAnalyze, onOpenHistory }) {
  const [url, setUrl] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [recentHistory, setRecentHistory] = useState([]);

  useEffect(() => {
    const fetchRecentHistory = async () => {
      // 아직 분석한 적 없는 브라우저면 ID를 새로 발급하지 않고 넘어간다
      if (!getSavedClientId()) {
        return;
      }

      try {
        const items = await listMyAnalyses();

        setRecentHistory(items.slice(0, 3));
      } catch (error) {
        console.error(
          "최근 분석 기록을 불러오지 못했습니다:",
          error
        );
      }
    };

    fetchRecentHistory();
  }, []);

  const handleSubmit = () => {
    const trimmedUrl = url.trim();

    if (!trimmedUrl) {
      return;
    }

    onAnalyze(trimmedUrl, isPublic);
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter") {
      handleSubmit();
    }
  };

  return (
    <section className="home">
      <div className="home-header">
        <p className="eyebrow">AI 기반 웹 보안 분석</p>

        <h2>
          이 웹사이트,
          <br />
          <span>안전할까요?</span>
        </h2>

        <p className="home-description">
          URL을 입력하면 다양한 보안 지표와 AI 분석을 통해
          피싱 위험 여부를 확인할 수 있습니다.
        </p>
      </div>

      <div className="url-card">
        <div className="url-card-label">URL 분석</div>

        <div className="url-input-row">
          <input
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com"
          />

          <button
            className="analyze-button"
            onClick={handleSubmit}
            disabled={!url.trim()}
          >
            분석하기
            <span>→</span>
          </button>
        </div>

        <p className="input-help">
          분석하려는 웹사이트의 URL을 입력해주세요.
        </p>

        <div className="visibility-options">
          <label
            className={`visibility-option ${
              !isPublic ? "selected" : ""
            }`}
          >
            <input
              type="radio"
              name="visibility"
              checked={!isPublic}
              onChange={() => setIsPublic(false)}
            />

            <div>
              <strong>비공개</strong>
              <span>
                이 브라우저에서만 분석 결과를 조회할 수 있습니다.
              </span>
            </div>
          </label>

          <label
            className={`visibility-option ${
              isPublic ? "selected" : ""
            }`}
          >
            <input
              type="radio"
              name="visibility"
              checked={isPublic}
              onChange={() => setIsPublic(true)}
            />

            <div>
              <strong>공개</strong>
              <span>
                다른 사용자도 분석 결과를 조회할 수 있습니다.
              </span>
            </div>
          </label>
        </div>
      </div>

      <div className="feature-grid">
        <div className="feature-card">
          <span className="feature-number">01</span>

          <h3>URL 분석</h3>

          <p>
            URL의 길이, 문자 패턴, 엔트로피 및 n-gram을
            분석합니다.
          </p>
        </div>

        <div className="feature-card">
          <span className="feature-number">02</span>

          <h3>AI 탐지</h3>

          <p>
            AI Agent가 여러 분석 결과를 종합하여
            의심스러운 특성을 판단합니다.
          </p>
        </div>

        <div className="feature-card">
          <span className="feature-number">03</span>

          <h3>웹페이지 분석</h3>

          <p>
            HTML, 텍스트 및 이미지 요소를 분석하여
            추가적인 위험 신호를 확인합니다.
          </p>
        </div>
      </div>

      <div className="recent-analysis">
        <div className="recent-analysis-header">
          <div>
            <p className="recent-eyebrow">
              RECENT ANALYSIS
            </p>

            <h3>최근 분석</h3>
          </div>

          <button
            className="recent-more-button"
            onClick={onOpenHistory}
          >
            전체 보기
            <span>→</span>
          </button>
        </div>

        {recentHistory.length === 0 ? (
          <div className="recent-empty">
            아직 분석한 기록이 없습니다.
          </div>
        ) : (
          <div className="recent-list">
            {recentHistory.map((item) => {
              const verdict = item.verdict;

              const statusClass =
                verdict === "phishing"
                  ? "danger"
                  : verdict === "suspicious"
                    ? "warning"
                    : "normal";

              const statusText =
                verdict === "phishing"
                  ? "피싱"
                  : verdict === "suspicious"
                    ? "의심"
                    : "정상";

              return (
                <div
                  className="recent-item"
                  key={item.id}
                >
                  <div className="recent-item-main">
                    <span
                      className={`recent-status ${statusClass}`}
                    >
                      {statusText}
                    </span>

                    <p>{item.url}</p>
                  </div>

                  <span className="recent-date">
                    {new Date(
                      item.created_at
                    ).toLocaleDateString("ko-KR")}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}

export default Home;