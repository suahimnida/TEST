import { useState } from "react";

import { deleteAnalysis, verifyOwner } from "../../services/api";
import PasswordInput from "../PasswordInput/PasswordInput";

import "./DeleteSection.css";

const CONFIRM_TEXT = "분석 결과를 삭제하겠습니다";

const ERRORS = {
  403: "성명 또는 사용자 식별 암호가 일치하지 않습니다.",
  404: "삭제할 수 있는 분석 결과가 없습니다. 성명과 식별 암호 없이 분석된 결과는 삭제할 수 없습니다.",
  429: "여러 번 틀려 15분 동안 확인할 수 없습니다. 잠시 후 다시 시도해 주세요.",
};

// 분석 결과 페이지 마지막의 "분석 결과 삭제"
// 1단계: 분석할 때 입력한 성명과 사용자 식별 암호 확인 → 2단계: 확인 문구 입력 후 "확인"
function DeleteSection({ analysisId, onDeleted }) {
  const [step, setStep] = useState(null); // null | secret | confirm
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const close = () => {
    setStep(null);
    setName("");
    setSecret("");
    setConfirmText("");
    setError("");
  };

  const ready = name.trim().length > 0 && /^[A-Za-z0-9]{8,12}$/.test(secret);

  const checkSecret = async () => {
    setBusy(true);
    setError("");
    try {
      await verifyOwner(analysisId, name.trim(), secret);
      setStep("confirm");
    } catch (e) {
      setError(ERRORS[e.status] || "본인 확인에 실패했습니다. 잠시 후 다시 시도해 주세요.");
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    setError("");
    try {
      await deleteAnalysis(analysisId, name.trim(), secret, confirmText);
      close();
      onDeleted();
    } catch (e) {
      setError(ERRORS[e.status] || "분석 결과를 삭제하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="result-section">
      <div className="delete-card">
        <div>
          <h3>분석 결과 삭제</h3>
          <p className="delete-warning">⚠ 분석을 요청한 본인만 삭제 가능합니다.</p>
          <p>
            분석할 때 입력한 성명과 사용자 식별 암호로 본인을 확인한 뒤 삭제해요. 삭제하면 분석 결과와 리포트,
            공유 링크가 모두 지워지고 되돌릴 수 없어요.
          </p>
        </div>
        <button className="delete-button" onClick={() => setStep("secret")}>
          분석 결과 삭제
        </button>
      </div>

      {step && (
        <div className="delete-overlay" role="dialog" aria-modal="true" aria-labelledby="delete-title">
          <div className="delete-dialog">
            <h3 id="delete-title">분석 결과 삭제</h3>

            {step === "secret" ? (
              <>
                <p>분석할 때 입력한 성명과 사용자 식별 암호를 입력해 주십시오.</p>
                <label className="delete-field">
                  <span>성명</span>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    maxLength={30}
                    placeholder="분석할 때 입력한 성명"
                    autoFocus
                  />
                </label>
                <label className="delete-field">
                  <span>사용자 식별 암호</span>
                  <PasswordInput
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && ready && !busy && checkSecret()}
                    maxLength={12}
                    placeholder="사용자 식별 암호 8~12자리"
                    autoComplete="off"
                  />
                </label>
              </>
            ) : (
              <>
                <p>
                  본인 확인이 끝났어요. 삭제하려면 아래 칸에 <strong>{CONFIRM_TEXT}</strong>를 정확히 입력한 뒤
                  확인을 눌러 주십시오.
                </p>
                <input
                  type="text"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder={CONFIRM_TEXT}
                  autoFocus
                />
              </>
            )}

            {error && <p className="delete-error">{error}</p>}

            <div className="delete-actions">
              <button className="delete-cancel" onClick={close} disabled={busy}>
                취소
              </button>
              {step === "secret" ? (
                <button
                  className="delete-next"
                  onClick={checkSecret}
                  disabled={busy || !ready}
                >
                  {busy ? "확인 중..." : "다음"}
                </button>
              ) : (
                <button
                  className="delete-confirm"
                  onClick={remove}
                  disabled={busy || confirmText.trim() !== CONFIRM_TEXT}
                >
                  {busy ? "삭제 중..." : "확인"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default DeleteSection;
