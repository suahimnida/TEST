import { useState } from "react";

import "./PasswordInput.css";

function EyeOpen() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
      <path
        d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}

function EyeClosed() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
      <path
        d="M3 10c2.2 3 5.3 5 9 5s6.8-2 9-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M6.5 13.6 5 16M12 15v2.8M17.5 13.6 19 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

// 사용자 식별 암호 입력란
// 눈을 뜬 아이콘을 누르면 암호가 보이고 눈을 감은 아이콘으로 바뀐다. 다시 누르면 원래대로 가려진다.
function PasswordInput({ className = "", ...props }) {
  const [visible, setVisible] = useState(false);

  return (
    <div className={`password-input ${className}`}>
      <input {...props} type={visible ? "text" : "password"} />
      <button
        type="button"
        className="password-toggle"
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? "암호 숨기기" : "암호 보기"}
        title={visible ? "암호 숨기기" : "암호 보기"}
      >
        {visible ? <EyeClosed /> : <EyeOpen />}
      </button>
    </div>
  );
}

export default PasswordInput;
