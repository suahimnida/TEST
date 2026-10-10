import { useEffect, useState } from "react";
import { getSavedClientId, listMyAnalyses } from "../../services/api";
import PasswordInput from "../../components/PasswordInput/PasswordInput";
import "./Home.css";

function Home({ onAnalyze, onOpenHistory }) {
  const [url, setUrl] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  // 분석 요청자 확인용: 공개 분석에 가린 성명으로 표시하고, 결과를 삭제할 때 식별 암호로 본인을 확인한다
  const [ownerName, setOwnerName] = useState("");
  const [ownerSecret, setOwnerSecret] = useState("");
  const [showErrors, setShowErrors] = useState(false);
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

  const nameError = !ownerName.trim() ? "성명을 입력해 주십시오." : "";
  const secretError = !/^[A-Za-z0-9]{8,12}$/.test(ownerSecret)
    ? "영어(대·소문자)와 숫자로 이루어진 8~12자리를 입력해 주십시오."
    : "";

  const handleSubmit = () => {
    const trimmedUrl = url.trim();

    if (!trimmedUrl) {
      return;
    }

    if (nameError || secretError) {
      setShowErrors(true);
      return;
    }

    onAnalyze(trimmedUrl, isPublic, ownerName.trim(), ownerSecret);
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

        <div className="owner-fields">
          <label className="owner-field">
            <span>성명</span>
            <input
              type="text"
              value={ownerName}
              onChange={(event) => setOwnerName(event.target.value)}
              maxLength={30}
              placeholder="성명을 입력하여 주십시오"
              autoComplete="name"
            />
            {showErrors && nameError && <small className="field-error">{nameError}</small>}
          </label>

          <label className="owner-field">
            <span>사용자 식별 암호</span>
            <PasswordInput
              value={ownerSecret}
              onChange={(event) => setOwnerSecret(event.target.value)}
              maxLength={12}
              placeholder="영어와 숫자로 이루어진 개인 식별 암호를 8~12자리로 입력하여 주십시오"
              autoComplete="new-password"
            />
            {showErrors && secretError ? (
              <small className="field-error">{secretError}</small>
            ) : (
              <small className="field-help">
                {ownerSecret.length}자 (8~12자리) · 분석 결과를 삭제할 때 본인 확인에 쓰여요. 꼭 기억해 두세요.
              </small>
            )}
          </label>
        </div>

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
                이 브라우저에서만 볼 수 있습니다. 결과 화면에서 공유 링크를 만들면
                링크가 있는 사람도 볼 수 있습니다.
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
                분석 기록의 '공개 분석'에서 누구나 결과를 볼 수 있습니다.
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

          <h3>AI 설명</h3>

          <p>
            AI가 탐지 근거와 유사 사례를 바탕으로
            왜 위험한지 설명하고 리포트를 작성합니다.
          </p>
        </div>

        <div className="feature-card">
          <span className="feature-number">03</span>

          <h3>평판 신호</h3>

          <p>
            사이트에 접속하지 않고 도메인 등록일, 인증서 기록,
            호스팅 정보를 확인합니다.
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