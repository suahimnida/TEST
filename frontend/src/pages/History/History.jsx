import { useEffect, useState } from "react";
import "./History.css";

import { getAnalysis, listMyAnalyses, listPublicAnalyses } from "../../services/api";

function History({ onViewResult, initialTab = "mine", notice = "" }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  // mine: 이 브라우저의 기록 / public: 다른 사용자가 공개한 결과
  const [tab, setTab] = useState(initialTab);

  useEffect(() => {
    const loadHistory = async () => {
      setLoading(true);
      try {
        const items = tab === "mine" ? await listMyAnalyses() : await listPublicAnalyses();

        setHistory(items);
      } catch (error) {
        console.error(
          "분석 기록을 불러오지 못했습니다:",
          error
        );
        setHistory([]);
      } finally {
        setLoading(false);
      }
    };

    loadHistory();
  }, [tab]);

  const tabs = (
    <div className="history-tabs" role="tablist">
      <button className={tab === "mine" ? "on" : ""} onClick={() => setTab("mine")} role="tab">
        내 기록
      </button>
      <button className={tab === "public" ? "on" : ""} onClick={() => setTab("public")} role="tab">
        공개 분석
      </button>
    </div>
  );

  const handleViewResult = async (item) => {
    try {
      const result = await getAnalysis(item.id);

      onViewResult(result);
    } catch (error) {
      console.error(
        "분석 결과를 불러오지 못했습니다:",
        error
      );

      alert(
        "분석 결과를 불러오지 못했습니다."
      );
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) {
      return "-";
    }

    return new Date(dateString).toLocaleString(
      "ko-KR",
      {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }
    );
  };

  const getRiskStatus = (verdict) => {
    if (verdict === "phishing") {
      return {
        label: "피싱 의심",
        className: "danger",
      };
    }

    if (verdict === "suspicious") {
      return {
        label: "주의 필요",
        className: "warning",
      };
    }

    return {
      label: "정상",
      className: "normal",
    };
  };

  if (loading) {
    return (
      <section className="history-page">
        <div className="history-header">
          <div>
            <p className="history-eyebrow">
              ANALYSIS HISTORY
            </p>

            <h2>분석 기록</h2>

            <p className="history-description">
              이전에 분석한 웹사이트의 결과를 확인할 수 있습니다.
            </p>
          </div>
        </div>

        {tabs}

        <div className="history-empty">
          <h3>분석 기록을 불러오는 중입니다.</h3>
        </div>
      </section>
    );
  }

  return (
    <section className="history-page">
      {/* Header */}
      <div className="history-header">
        <div>
          <p className="history-eyebrow">
            ANALYSIS HISTORY
          </p>

          <h2>분석 기록</h2>

          <p className="history-description">
            이전에 분석한 웹사이트의 결과를 확인할 수 있습니다.
          </p>
        </div>

        <div className="history-count">
          <span>{history.length}</span>
          <small>건</small>
        </div>
      </div>

      {tabs}

      {notice && <p className="history-notice">{notice}</p>}

      {/* Empty */}
      {history.length === 0 ? (
        <div className="history-empty">
          <div className="history-empty-icon">
            ◷
          </div>

          <h3>{tab === "mine" ? "분석 기록이 없습니다." : "공개된 분석 결과가 없습니다."}</h3>
          <p>
            {tab === "mine"
              ? "웹사이트를 분석하면 이곳에서 분석 기록을 확인할 수 있습니다."
              : "분석할 때 '공개'를 선택하거나 결과 화면에서 공개로 바꾸면 이곳에 표시됩니다."}
          </p>
        </div>
      ) : (
        <div className="history-list">
          {history.map((item) => {
            const riskStatus = getRiskStatus(
              item.verdict
            );

            return (
              <article
                className="history-card"
                key={item.id}
              >
                <div className="history-card-main">
                  {/* Status / Date */}
                  <div className="history-card-top">
                    <span
                      className={`history-status ${riskStatus.className}`}
                    >
                      {riskStatus.label}
                    </span>

                    <span className="history-date">
                      {formatDate(item.created_at)}
                    </span>
                    {tab === "public" && item.owner_name && (
                      <span className="history-owner">{item.owner_name}</span>
                    )}
                  </div>

                  {/* URL */}
                  <h3>{item.url}</h3>

                  {/* Summary */}
                  <p>
                    분석 결과를 확인하려면
                    결과 보기를 눌러주세요.
                  </p>
                </div>

                {/* Actions */}
                <div className="history-card-actions">
                  <button
                    className="history-view-button"
                    onClick={() =>
                      handleViewResult(item)
                    }
                  >
                    결과 보기
                    <span>→</span>
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default History;

