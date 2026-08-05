# 설치 검증 순서

```powershell
.\Publish-MailShieldAgent.ps1
.\Verify-MailShieldPackage.ps1
.\Install-MailShieldAgent.ps1
.\Verify-MailShieldService.ps1
```

`Install-MailShieldAgent.ps1`는 관리자 권한 PowerShell에서 실행합니다. 서비스 검증은 설치 후 `Running` 및 `Automatic` 상태를 확인하고 최근 Service Control Manager 이벤트를 출력합니다.
