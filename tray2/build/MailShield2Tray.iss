; MailShield 2 설치기 (사용자별 설치, 관리자 권한 불필요)
; 빌드: tray\build\Build-MailShield2Tray.ps1 가 dist\MailShield2Tray.exe 생성 후 호출한다.

#define MyAppName "MailShield 2"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "MailShield"
#define MyAppExeName "MailShield2Tray.exe"

[Setup]
AppId={{9F2C7A41-6B83-4D52-BE17-3A5C0D8E4B77}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\MailShield2\Tray
DefaultGroupName=MailShield2
DisableProgramGroupPage=yes
OutputDir=..\output
OutputBaseFilename=MailShield2Tray-Setup-{#MyAppVersion}
SetupIconFile=MailShield2Tray.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Windows 로그인 시 자동 실행"; GroupDescription: "추가 작업:"
Name: "desktopicon"; Description: "바탕 화면 바로 가기 만들기"; GroupDescription: "추가 작업:"; Flags: unchecked

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} 계정 설정"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--settings"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "MailShield2Tray"; ValueData: """{app}\{#MyAppExeName}"" --autostart"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--setup"; Description: "지금 MailShield 2 시작(처음 설정 마법사 열기)"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; 실행 중인 인스턴스 종료 후 자격증명·상태·자동 시작 항목 정리
Filename: "taskkill.exe"; Parameters: "/IM {#MyAppExeName} /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillTray"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "Cleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\MailShield2"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    MsgBox('MailShield 2를 제거합니다.'#13#10 +
           '저장된 앱 비밀번호·Google 로그인 정보와 감시 상태도 함께 삭제됩니다.', mbInformation, MB_OK);
end;
