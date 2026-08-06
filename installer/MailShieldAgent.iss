#define MyAppName "MailShield Agent"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "MailShield"
#define MyAppExeName "MailShield.Agent.exe"

[Setup]
AppId={{C9C2A2A1-0E1F-4A0D-9D7B-1BB5A8B7AA10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\MailShield\Agent
DefaultGroupName=MailShield
OutputDir=output
OutputBaseFilename=MailShieldAgent-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
Uninstallable=yes
WizardStyle=modern

[Files]
Source: "publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
Filename: "sc.exe"; Parameters: "create MailShieldAgent binPath= ""{app}\MailShield.Agent.exe"" start= auto DisplayName= ""MailShield Agent"""; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "description MailShieldAgent ""MailShield email security monitoring agent"""; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "start MailShieldAgent"; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop MailShieldAgent"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "delete MailShieldAgent"; Flags: runhidden waituntilterminated

[Code]
function InitializeSetup(): Boolean;
begin
  MsgBox('MailShield Agent는 관리자 권한으로 Windows Service를 설치합니다.'#13#10 +
         '현재 버전은 코드 서명 전 내부 테스트용입니다.', mbInformation, MB_OK);
  Result := True;
end;
