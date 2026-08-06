# MailShield Agent 설치

현재 설치 스크립트는 서명 전 검증용입니다. 운영 배포 전에는 MSI/MSIX 패키지, 코드 서명 인증서, 관리자 권한 정책, 자동 롤백과 업그레이드 검증을 추가해야 합니다.

```powershell
Set-Location "C:\Users\이상진\Documents\email_checker"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Publish-MailShieldAgent.ps1
.\Verify-MailShieldPackage.ps1
.\Install-MailShieldAgent.ps1
.\Verify-MailShieldService.ps1
```

현재 위치가 `C:\Windows\System32`라면 상대경로가 실패합니다. `Set-Location`을 먼저 실행하거나 저장소 절대경로를 사용하십시오. 실행 정책 확인창 없이 일회성으로 실행하려면 다음처럼 실행합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\이상진\Documents\email_checker\installer\Publish-MailShieldAgent.ps1"
```

IMAP 앱 비밀번호는 파일에 저장하지 말고 보안 저장소에 등록해야 합니다. 현재 MailKit 보안 권고가 남아 있으므로 내부 테스트용으로만 설치하십시오.
