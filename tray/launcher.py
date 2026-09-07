"""PyInstaller 진입점. 패키지를 절대 임포트해야 frozen 환경에서 상대 임포트가 동작한다."""

import sys

from mailshield_tray.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
