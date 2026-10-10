import { useEffect, useState } from "react";
import { analyzeUrl } from "../../services/api";
import "./Analysis.css";

// 실제 백엔드 처리 순서. 사이트에는 접속하지 않으므로 HTML·이미지 분석 단계는 없다
const analysisSteps = [
  {
    title: "KISA 블랙리스트",
    description: "한국인터넷진흥원 피싱 사이트 목록과 비교",
  },
  {
    title: "URL 구조",
    description: "URL 문자열의 구조, 키워드, 경로 패턴 분석",
  },
  {
    title: "ML 판정",
    description: "URL 문자 패턴으로 학습한 모델로 위험도 계산",
  },
  {
    title: "평판 신호",
    description: "도메인 등록일, 인증서 기록, 호스팅 정보 조회 (사이트에는 접속하지 않음)",
  },
  {
    title: "유사 사례·AI 설명",
    description: "비슷한 과거 사례를 찾고 AI가 판단 근거를 설명",
  },
];

function Analysis({ url, isPublic, onComplete }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const runAnalysis = async () => {
      try {
        setError("");
        setCurrentStep(0);

        const result = await analyzeUrl(url, isPublic);

        if (!cancelled) {
          onComplete(result);
        }
      } catch (error) {
        console.error("분석 요청 실패:", error);

        if (!cancelled) {
          setError(
            "분석 서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요."
          );
        }
      }
    };

    runAnalysis();

    return () => {
      cancelled = true;
    };
  }, [url, isPublic, onComplete]);

  useEffect(() => {
    if (error) {
      return;
    }

    const timer = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= analysisSteps.length - 1) {
          return prev;
        }

        return prev + 1;
      });
    }, 1200);

    return () => clearInterval(timer);
  }, [error]);

  const currentStepData =
    analysisSteps[currentStep] || analysisSteps[analysisSteps.length - 1];

  return (
    <section className="analysis-page">
      <div className="analysis-header">
        <p className="eyebrow">URL 보안 분석</p>

        <h2>URL 분석 중</h2>

        <p className="analysis-description">
          여러 보안 지표를 분석하여 해당 웹사이트의
          피싱 위험 가능성을 확인하고 있습니다.
        </p>
      </div>

      <div className="target-card">
        <div className="target-label">분석 대상 URL</div>
        <div className="target-url">{url}</div>
      </div>

      <div className="pipeline-card">
        <div className="pipeline-header">
          <div>
            <p className="pipeline-label">분석 과정</p>
            <h3>보안 검사</h3>
          </div>

          <span
            className={`pipeline-status ${error ? "error" : ""}`}
          >
            {error ? "연결 오류" : "분석 중"}
          </span>
        </div>

        <div className="analysis-steps">
          {analysisSteps.map((step, index) => {
            const isCompleted = index < currentStep;
            const isActive = index === currentStep;

            return (
              <div
                className={`analysis-step ${
                  isCompleted ? "completed" : ""
                } ${isActive ? "active" : ""}`}
                key={step.title}
              >
                <div className="step-icon">
                  {isCompleted
                    ? "✓"
                    : isActive
                    ? "●"
                    : "○"}
                </div>

                <div className="step-content">
                  <h4>{step.title}</h4>
                  <p>{step.description}</p>
                </div>

                <span className="step-status">
                  {isCompleted
                    ? "완료"
                    : isActive
                    ? "분석 중"
                    : "대기 중"}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {error ? (
        <div className="analysis-error">
          <strong>분석 서버에 연결할 수 없습니다.</strong>

          <p>
            백엔드 서버가 실행 중인지 확인한 후 다시 시도해주세요.
          </p>
        </div>
      ) : (
        <div className="analysis-footer">
          <span className="loading-dot"></span>
          {currentStepData.title}을(를) 분석하고 있습니다...
        </div>
      )}
    </section>
  );
}

export default Analysis;