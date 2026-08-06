# Installer.exe 생성 방법

`MailShieldAgent-Setup.exe`는 Inno Setup으로 생성합니다.

## 1. 준비

- Windows용 Inno Setup 설치
- 먼저 self-contained publish 실행

```powershell
.\installer\Publish-MailShieldAgent.ps1 -OutputPath .\installer\publish
```

## 2. 설치 파일 생성

Inno Setup Compiler에서 `installer\MailShieldAgent.iss`를 열고 Compile을 누릅니다. 또는 명령줄에서:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" ".\installer\MailShieldAgent.iss"
```

생성 파일:

```text
installer\output\MailShieldAgent-Setup.exe
```

## 3. 설치 동작

설치 프로그램은 관리자 권한 UAC를 요청하고 다음을 수행합니다.

1. `C:\Program Files\MailShield\Agent`에 파일 복사
2. `MailShieldAgent` Windows Service 생성
3. 자동 시작 설정
4. 서비스 시작

제거 시 서비스를 중지하고 삭제합니다.

## 4. 상용 배포 전 필수 작업

- Inno Setup 설치 파일 코드 서명
- 설치 파일 SHA-256 공개 및 릴리스 태그 연결
- MailKit/MimeKit 보안 권고 해결
- 업그레이드·롤백·서비스 중지 실패 테스트
- 실제 `appsettings.json`과 비밀정보를 설치 패키지에 포함하지 않기
