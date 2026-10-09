import { useState } from "react";

import {
  createReport,
  fetchReportPdf,
  reportFileName,
} from "../../services/api";

import "./ReportSection.css";

const verdictLabels = {
  phishing: "피싱",
  suspicious: "의심",
  normal: "정상",
};

const levelLabels = {
  safe: "안전",
  caution: "주의",
  warning: "경고",
  danger: "위험",
};

function modelLabel(name) {
  return name === "template" ? "기본 템플릿" : name;
}

function formatTime(iso) {
  if (!iso) {
    return "-";
  }

  return new Date(iso).toLocaleString("ko-KR", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

// PDF Blob을 사용자가 고른 위치에 저장한다.
// 크롬·엣지는 저장 위치를 고르는 창을 띄우고, 지원하지 않는 브라우저는 다운로드 폴더에 저장한다.
async function savePdf(analysisId) {
  const fileName = reportFileName(analysisId);

  if (window.showSaveFilePicker) {
    let handle;

    try {
      // 저장 창은 클릭 직후에 열어야 해서 PDF를 받기 전에 먼저 띄운다
      handle = await window.showSaveFilePicker({
        suggestedName: fileName,
        types: [
          {
            description: "PDF 문서",
            accept: { "application/pdf": [".pdf"] },
          },
        ],
      });
    } catch (error) {
      if (error.name === "AbortError") {
        return "cancelled";
      }

      handle = null; // 저장 창을 쓸 수 없는 환경이면 일반 다운로드로
    }

    if (handle) {
      const blob = await fetchReportPdf(analysisId);
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return "saved";
    }
  }

  const blob = await fetchReportPdf(analysisId);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return "downloaded";
}

function ReportSection({ analysisId }) {
  const [report, setReport] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | loading | error
  const [pdfBusy, setPdfBusy] = useState(null); // view | save | null
  const [message, setMessage] = useState("");

  async function handleGenerate(regenerate = false) {
    setStatus("loading");
    setMessage("");

    try {
      setReport(await createReport(analysisId, regenerate));
      setStatus("idle");
    } catch (error) {
      console.error(error);
      setStatus("error");
      setMessage(
        "리포트를 만들지 못했습니다. 잠시 후 다시 시도해 주세요."
      );
    }
  }

  async function handleView() {
    // 팝업 차단을 피하려고 클릭 직후 빈 창을 먼저 연다
    const viewer = window.open("", "_blank");
    setPdfBusy("view");
    setMessage("");

    try {
      const blob = await fetchReportPdf(analysisId);
      const url = URL.createObjectURL(blob);

      if (viewer) {
        viewer.location.href = url;
      } else {
        setMessage(
          "브라우저가 새 창을 막았습니다. 'PDF 저장'으로 내려받아 확인해 주세요."
        );
      }

      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (error) {
      console.error(error);
      viewer?.close();
      setMessage("PDF를 만들지 못했습니다.");
    } finally {
      setPdfBusy(null);
    }
  }

  async function handleSave() {
    setPdfBusy("save");
    setMessage("");

    try {
      const result = await savePdf(analysisId);

      if (result === "saved") {
        setMessage("PDF를 선택한 위치에 저장했습니다.");
      } else if (result === "downloaded") {
        setMessage("PDF를 다운로드 폴더에 저장했습니다.");
      }
    } catch (error) {
      console.error(error);
      setMessage("PDF를 저장하지 못했습니다.");
    } finally {
      setPdfBusy(null);
    }
  }

  const loading = status === "loading";

  return (
    <>
      <div className="report-card">
        <div>
          <p className="report-label">자동 리포트</p>

          <h3>AI 분석 리포트 생성</h3>

          <p>
            탐지 결과, 유사 사례, AI 분석 설명을 바탕으로 후속 조치를 조사하고
            신고 기관까지 정리한 보안 분석 리포트를 생성합니다.
          </p>
        </div>

        <button
          className="report-button"
          onClick={() => handleGenerate(Boolean(report))}
          disabled={loading}
        >
          {loading
            ? "리포트 작성 중..."
            : report
            ? "리포트 다시 생성"
            : "리포트 생성"}
          <span>→</span>
        </button>
      </div>

      {loading && (
        <p className="report-status">
          AI가 후속 조치를 조사하고 리포트를 작성하고 있습니다. 20~40초 정도 걸릴 수 있습니다.
        </p>
      )}

      {message && <p className="report-status">{message}</p>}

      {report && (
        <article className="report-panel">
          <header className="report-panel-header">
            <div>
              <p className="report-label">분석 리포트</p>
              <h3>피싱 URL 분석 리포트</h3>
              <p className="report-meta">
                작성 {formatTime(report.created_at)} · 리포트 작성{" "}
                {modelLabel(report.generated_by)} · 후속 조치 조사{" "}
                {modelLabel(report.followup_by)}
              </p>
            </div>

            <div className="report-pdf-buttons">
              <button
                className="report-pdf-button secondary"
                onClick={handleView}
                disabled={pdfBusy !== null}
              >
                {pdfBusy === "view" ? "PDF 만드는 중..." : "PDF 보기"}
              </button>

              <button
                className="report-pdf-button"
                onClick={handleSave}
                disabled={pdfBusy !== null}
              >
                {pdfBusy === "save" ? "저장 중..." : "PDF 저장"}
              </button>
            </div>
          </header>

          <div className="report-verdict">
            <strong>
              {report.risk_score !== null
                ? report.risk_score.toFixed(1)
                : "-"}
            </strong>
            <span>
              판정 {verdictLabels[report.verdict] || "판정 불가"} · 등급{" "}
              {levelLabels[report.risk_level] || "-"} · 신뢰도{" "}
              {report.confidence !== null
                ? `${Math.round(report.confidence * 100)}%`
                : "-"}
            </span>
          </div>

          <section className="report-block">
            <h4>1. 요약</h4>
            <p>{report.summary}</p>
          </section>

          <section className="report-block">
            <h4>2. 판정 근거</h4>
            <ul className="report-evidence">
              {report.evidence.map((item, index) => (
                <li key={`${item.source}-${index}`}>
                  <span
                    className={`report-badge ${
                      item.used_in_verdict ? "used" : ""
                    }`}
                  >
                    {item.used_in_verdict ? "판정 반영" : "참고"}
                  </span>
                  <div>
                    <strong>{item.source}</strong>
                    <p>{item.finding}</p>
                  </div>
                </li>
              ))}
            </ul>
          </section>

          <section className="report-block">
            <h4>3. 유사 사례</h4>
            {report.similar_cases?.length > 0 ? (
              <ul className="report-cases">
                {report.similar_cases.map((item) => (
                  <li key={item.url}>
                    <span
                      className={`report-badge ${
                        item.label === 1 ? "danger" : "used"
                      }`}
                    >
                      {item.label === 1 ? "피싱" : "정상"}
                    </span>
                    <span className="report-case-url">{item.url}</span>
                    <span className="report-case-sim">
                      {Math.round(item.similarity * 100)}%
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p>유사 사례를 찾지 못했습니다.</p>
            )}
          </section>

          <section className="report-block">
            <h4>4. AI 분석 설명</h4>
            <p>
              {report.ai_analysis || "AI 분석 설명이 제공되지 않았습니다."}
            </p>
          </section>

          <section className="report-block">
            <h4>5. 위험 분석</h4>
            <p>{report.risk_assessment}</p>
          </section>

          <section className="report-block">
            <h4>6. 후속 조치</h4>
            <div className="report-research">
              <strong>조사 결과</strong>
              <p>{report.followup_summary}</p>
            </div>
            <p className="report-hint">
              본인의 상황에 해당하는 항목을 펼쳐 확인하세요. '우선' 표시는 이
              URL에 특히 중요한 조치입니다.
            </p>

            {report.action_groups.map((group) => {
              const hasPriority = group.actions.some(
                (action) => action.priority
              );

              return (
                <details
                  className="report-group"
                  key={group.situation}
                  open={hasPriority}
                >
                  <summary>{group.situation}</summary>

                  {group.actions.map((action) => (
                    <div className="report-action" key={action.id}>
                      <h5>
                        {action.priority && (
                          <span className="report-badge priority">우선</span>
                        )}
                        {action.title}
                      </h5>

                      {action.note && (
                        <p className="report-note">{action.note}</p>
                      )}

                      <ul>
                        {action.steps.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </details>
              );
            })}
          </section>

          <section className="report-block">
            <h4>7. 신고·상담 기관</h4>
            <div className="report-contacts">
              {report.contacts.map((contact) => (
                <div className="report-contact" key={contact.name}>
                  <strong>{contact.name}</strong>
                  <p>{contact.purpose}</p>
                  <div>
                    {contact.phone && (
                      <a href={`tel:${contact.phone}`}>☎ {contact.phone}</a>
                    )}
                    {contact.url && (
                      <a
                        href={contact.url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {contact.url.replace("https://", "")}
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="report-block">
            <h4>8. 분석의 한계</h4>
            <ul className="report-limitations">
              {report.limitations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        </article>
      )}
    </>
  );
}

export default ReportSection;
