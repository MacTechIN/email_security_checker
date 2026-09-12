"""개발 환경용 실행기. 더블클릭 또는 자동 시작 항목에서 콘솔 없이 실행한다.

패키징된 exe에서는 사용하지 않는다(PyInstaller가 mailshield2/__main__.py를 진입점으로 쓴다).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mailshield2.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
