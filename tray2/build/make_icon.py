"""빌드 시 exe·설치기용 아이콘(.ico)을 생성한다."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mailshield2.ui import icons  # noqa: E402

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "MailShield2Tray.ico"
    target.parent.mkdir(parents=True, exist_ok=True)
    icons.save_ico(str(target))
    print(target)
