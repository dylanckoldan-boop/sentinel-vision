; Sentinel Vision - Windows installer (Inno Setup 6)
;
; Build (after `pyinstaller packaging/sentinel_vision.spec`):
;   iscc /DAppVersion=0.2.0 packaging\windows\SentinelVision.iss
; Output: dist\installer\SentinelVision-<version>-Setup.exe
;
; Command-line switches understood by the installer (besides Inno's /SILENT, /VERYSILENT, /DIR=...):
;   /TASKS="autostart,desktopicon,addtopath"   choose options in silent installs
;   /CURRENTUSER or /ALLUSERS                  install for this user (default, no admin) or all users
;   /RELAUNCH=1                                start the app after a silent install (used by self-update)

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\SentinelVision"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\installer"
#endif

#define AppName "Sentinel Vision"
#define AppExe "SentinelVision.exe"
#define CliExe "sentinel-vision-cli.exe"
#define AppUrl "https://github.com/dylanckoldan-boop/sentinel-vision"
#define RunValue "SentinelVision"
#define RunKey "Software\Microsoft\Windows\CurrentVersion\Run"

[Setup]
AppId={{9D3C2B71-6A4E-4F0B-9E57-2C1A8D4B5E60}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Sentinel Vision contributors
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
AppCopyright=MIT License
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
UsePreviousPrivileges=yes
UsePreviousTasks=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=..\..\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=SentinelVision-{#AppVersion}-Setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=force
RestartApplications=no
SetupMutex=SentinelVisionSetupMutex

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start Sentinel Vision automatically when I sign in (recommended - protection only runs while the app runs)"; GroupDescription: "Protection:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add the sentinel-vision-cli command-line tool to PATH"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; remove files of the previous version so stale libraries never mix with new ones
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Open-source antimalware"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; HKA = HKCU for a per-user install, HKLM for an all-users install. The app reads/writes the same value.
Root: HKA; Subkey: "{#RunKey}"; ValueType: string; ValueName: "{#RunValue}"; ValueData: """{app}\{#AppExe}"" --minimized"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent runasoriginaluser
Filename: "{app}\{#AppExe}"; Flags: nowait runasoriginaluser; Check: RelaunchRequested

[UninstallRun]
; remove hidden ransomware decoys, start-at-sign-in and (asking for permission) hosts-file blocking
Filename: "{app}\{#CliExe}"; Parameters: "uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "SVCleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Code]
const
  EnvKeyUser = 'Environment';
  EnvKeyMachine = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function RelaunchRequested(): Boolean;
begin
  Result := WizardSilent() and (ExpandConstant('{param:RELAUNCH|0}') = '1');
end;

procedure KillImage(const Image: String);
var
  ResultCode, I: Integer;
begin
  { taskkill exits with 128 once no process with that image name is left; keep going until then. }
  for I := 1 to 40 do
  begin
    if not Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM ' + Image, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      exit;
    if ResultCode = 128 then
      exit;
    Sleep(500);
  end;
end;

procedure StopRunningApp();
begin
  { The app keeps running in the tray, so a normal close request would only hide it: end it so files can be replaced. }
  KillImage('{#AppExe}');
  KillImage('{#CliExe}');
  Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningApp();
  Result := '';
end;

{ ---------- PATH handling (per-user or machine-wide, matching the install mode) ---------- }

function EnvRoot(): Integer;
begin
  if IsAdminInstallMode() then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvKey(): String;
begin
  if IsAdminInstallMode() then
    Result := EnvKeyMachine
  else
    Result := EnvKeyUser;
end;

function PathContains(const Paths, Dir: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

procedure AddToPath(const Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(EnvRoot(), EnvKey(), 'Path', Paths) then
    Paths := '';
  if PathContains(Paths, Dir) then
    exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  Paths := Paths + Dir;
  RegWriteExpandStringValue(EnvRoot(), EnvKey(), 'Path', Paths);
end;

procedure RemoveFromPath(const Dir: String);
var
  Paths, Rest, Item, NewPaths: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot(), EnvKey(), 'Path', Paths) then
    exit;
  if not PathContains(Paths, Dir) then
    exit;
  NewPaths := '';
  Rest := Paths + ';';
  while Length(Rest) > 0 do
  begin
    P := Pos(';', Rest);
    Item := Copy(Rest, 1, P - 1);
    Delete(Rest, 1, P);
    if (Item <> '') and (Uppercase(Item) <> Uppercase(Dir)) then
    begin
      if NewPaths <> '' then
        NewPaths := NewPaths + ';';
      NewPaths := NewPaths + Item;
    end;
  end;
  RegWriteExpandStringValue(EnvRoot(), EnvKey(), 'Path', NewPaths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');
    if WizardIsTaskSelected('addtopath') then
      AddToPath(AppDir)
    else
      RemoveFromPath(AppDir);
    { Unticking "start at sign-in" on an upgrade must really turn it off (including a value the app wrote). }
    if not WizardIsTaskSelected('autostart') then
    begin
      RegDeleteValue(HKEY_CURRENT_USER, '{#RunKey}', '{#RunValue}');
      if IsAdminInstallMode() then
        RegDeleteValue(HKEY_LOCAL_MACHINE, '{#RunKey}', '{#RunValue}');
    end;
  end;
end;

{ ---------- uninstall ---------- }

function InitializeUninstall(): Boolean;
begin
  StopRunningApp();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveFromPath(ExpandConstant('{app}'));
    { the app itself may have written the per-user value from its Protection page }
    RegDeleteValue(HKEY_CURRENT_USER, '{#RunKey}', '{#RunValue}');
    if IsAdminInstallMode() then
      RegDeleteValue(HKEY_LOCAL_MACHINE, '{#RunKey}', '{#RunValue}');
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\SentinelVision');
    if DirExists(DataDir) and (not UninstallSilent()) then
    begin
      if MsgBox('Also delete Sentinel Vision''s data?' + #13#10#13#10 +
                'This includes settings, detection history, downloaded definitions, the encrypted quarantine and the ' +
                'rollback vault (encrypted earlier versions of your documents). Your own documents are not affected.' + #13#10#13#10 +
                'Choose No to keep it for a future reinstall.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
