"""MailShield Tray - Windows 상주형 이메일 감시 앱 (1단계, 개인·파일럿용).

`docs/02.개발계획서.md` 18장 전환 계획의 1단계 구현이다.
검증된 `code_snipt/realtime_email_monitor.pyw`의 감시·탐지 로직을 재사용하고,
트레이 UI, Toast 알림, 자격증명 보안 저장, 체크포인트, 자동 시작, 단일 인스턴스를 더한다.
"""

APP_NAME = "MailShield"
APP_DISPLAY_NAME = "MailShield Tray"
VERSION = "0.1.11"
