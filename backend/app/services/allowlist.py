"""공식 도메인 허용 목록.

목록에 있는 도메인은 ML 점수만으로 피싱 판정을 내리지 않는다 (KISA 블랙리스트는 그대로 우선).
누구나 페이지를 올릴 수 있는 서비스는 목록에 있어도 항상 제외한다. 이런 곳은 피싱 페이지가 실제로 자주 올라온다.

목록 파일: resources/allowlist/domains.txt (scripts/build_allowlist.py 로 생성)
"""

import logging
import sys
from pathlib import Path

from app.schemas import AllowlistResult

_ML_DIR = Path(__file__).resolve().parents[2] / "ml_integration"
if str(_ML_DIR) not in sys.path:
    sys.path.append(str(_ML_DIR))

from url_features import registered_domain, split_url  # noqa: E402

logger = logging.getLogger(__name__)

_PATH = Path(__file__).resolve().parents[2] / "resources" / "allowlist" / "domains.txt"

# 이 도메인 아래는 사용자가 만든 페이지라서 허용하지 않는다 (호스트 끝부분이 같으면 제외)
USER_CONTENT = (
    "blogspot.com", "blogger.com", "weebly.com", "wixsite.com", "wordpress.com", "github.io",
    "githubusercontent.com", "googleusercontent.com", "sites.google.com", "docs.google.com",
    "drive.google.com", "forms.gle", "script.google.com", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "web.app", "firebaseapp.com", "appspot.com", "pages.dev",
    "workers.dev", "r2.dev", "vercel.app", "netlify.app", "herokuapp.com", "glitch.me", "notion.site",
    "000webhostapp.com", "azurewebsites.net", "blob.core.windows.net", "cloudfront.net", "amazonaws.com",
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "dropboxusercontent.com", "linktr.ee",
    "form.naver.com", "ngrok.io", "ngrok-free.app", "t.me", "wa.me",
)

_domains: set | None = None


def _load() -> set:
    global _domains
    if _domains is None:
        try:
            lines = _PATH.read_text(encoding="utf-8").splitlines()
            _domains = {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}
        except FileNotFoundError:
            logger.warning("허용 목록 파일이 없어 허용 목록 없이 동작합니다: %s", _PATH)
            _domains = set()
    return _domains


def _is_user_content(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in USER_CONTENT)


def check(url: str) -> AllowlistResult:
    host = split_url(url)["host"].lower().strip(".")
    if not host or _is_user_content(host):
        return AllowlistResult()
    domain = registered_domain(host)
    if domain in _load():
        return AllowlistResult(matched=True, domain=domain)
    return AllowlistResult()
