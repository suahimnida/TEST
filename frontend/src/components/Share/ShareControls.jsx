import { useState } from "react";

import {
  createShareLink,
  revokeShareLink,
  setVisibility,
  shareUrl,
} from "../../services/api";

import "./ShareControls.css";

// 결과 화면 위쪽의 공개 범위·공유 링크 영역
// viewer: owner(내 결과) / public(남의 공개 결과) / shared(공유 링크로 연 결과)
function ShareControls({ result, onChange }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  if (result.viewer === "shared") {
    return (
      <div className="share-panel readonly">
        <strong>공유 링크로 열람 중</strong>
        <p>분석한 사람이 링크로 공유한 결과예요. 읽기 전용이며 공개 범위는 바꿀 수 없어요.</p>
      </div>
    );
  }

  if (result.viewer !== "owner") {
    return (
      <div className="share-panel readonly">
        <strong>공개된 분석 결과</strong>
        <p>다른 사용자가 공개한 결과예요. 읽기 전용이에요.</p>
      </div>
    );
  }

  const link = result.share_token ? shareUrl(result.share_token) : "";

  async function run(action, done) {
    setBusy(true);
    setMessage("");
    try {
      await action();
      if (done) setMessage(done);
    } catch (error) {
      console.error(error);
      setMessage("처리하지 못했어요. 잠시 후 다시 시도해 주세요.");
    } finally {
      setBusy(false);
    }
  }

  const changeVisibility = (isPublic) =>
    run(async () => {
      const updated = await setVisibility(result.id, isPublic);
      onChange({ ...result, ...updated });
    }, isPublic ? "공개로 바꿨어요. 분석 기록의 '공개 분석'에 표시돼요." : "비공개로 바꿨어요.");

  const turnOnLink = () =>
    run(async () => {
      const token = await createShareLink(result.id);
      onChange({ ...result, share_token: token });
    });

  const turnOffLink = () =>
    run(async () => {
      await revokeShareLink(result.id);
      onChange({ ...result, share_token: null });
    }, "공유를 중지했어요. 이미 보낸 링크는 더 이상 열리지 않아요.");

  const copyLink = () =>
    run(async () => {
      await navigator.clipboard.writeText(link);
    }, "링크를 복사했어요.");

  return (
    <div className="share-panel">
      <div className="share-row">
        <div>
          <strong>공개 범위</strong>
          <p>
            {result.is_public
              ? "누구나 분석 기록의 '공개 분석'에서 이 결과를 볼 수 있어요."
              : "이 브라우저에서만 볼 수 있어요."}
          </p>
        </div>
        <div className="share-toggle" role="group" aria-label="공개 범위">
          <button
            className={!result.is_public ? "on" : ""}
            onClick={() => changeVisibility(false)}
            disabled={busy || !result.is_public}
          >
            비공개
          </button>
          <button
            className={result.is_public ? "on" : ""}
            onClick={() => changeVisibility(true)}
            disabled={busy || result.is_public}
          >
            공개
          </button>
        </div>
      </div>

      <div className="share-row">
        <div>
          <strong>링크가 있는 사람은 볼 수 있음</strong>
          <p>
            {result.share_token
              ? "아래 링크를 받은 사람은 비공개여도 이 결과를 볼 수 있어요."
              : "공개하지 않고 원하는 사람에게만 결과를 보여 주고 싶을 때 써요."}
          </p>
        </div>
        {result.share_token ? (
          <button className="share-secondary" onClick={turnOffLink} disabled={busy}>
            공유 중지
          </button>
        ) : (
          <button className="share-primary" onClick={turnOnLink} disabled={busy}>
            링크 만들기
          </button>
        )}
      </div>

      {result.share_token && (
        <div className="share-link">
          <input value={link} readOnly onFocus={(e) => e.target.select()} aria-label="공유 링크" />
          <button className="share-primary" onClick={copyLink} disabled={busy}>
            복사
          </button>
        </div>
      )}

      {message && <p className="share-message">{message}</p>}
    </div>
  );
}

export default ShareControls;
