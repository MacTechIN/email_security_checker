; MailShield 2 설치기 - 폴더형(onedir / Nuitka standalone) 배포용
; 실행 파일 하나가 아니라 폴더 전체를 설치한다. 프로세스 1개, 임시 폴더 추출 없음.
; 빌드: ISCC.exe /DSrcDir="C:\ms_build\out\launcher.dist" build\MailShield2Tray-dir.iss
;       (SrcDir을 주지 않으면 ..\dist-onedir\MailShield2Tray 를 쓴다)

#define MyAppName "MailShield 2"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "MailShield"
#define MyAppExeName "MailShield2Tray.exe"
#ifndef SrcDir
  #define SrcDir "..\dist-onedir\MailShield2Tray"
#endif

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
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} 계정 설정"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--settings"
Name: "{group}\{#MyAppName} 연결 점검"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--verify --gui"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "MailShield2Tray"; ValueData: """{app}\{#MyAppExeName}"" --autostart"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; 설치 직후 처음 설정 마법사: 이메일 → 2단계 인증·앱 비밀번호 페이지 안내 → 검사 → 통과 시 저장·감시 시작
Filename: "{app}\{#MyAppExeName}"; Parameters: "--setup"; Description: "지금 MailShield 2 시작(처음 설정 마법사 열기)"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/IM {#MyAppExeName} /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillTray"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "Cleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\MailShield2"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    MsgBox('MailShield 2를 제거합니다.'#13#10 +
           '저장된 앱 비밀번호·Google 로그인 정보와 감시 상태도 함께 삭제됩니다.', mbInformation, MB_OK);
end;
