; Sentinel Vision - Windows installer (Inno Setup 6.3+ / 7)
;
; Build (after `pyinstaller packaging/sentinel_vision.spec`):
;   iscc /DAppVersion=0.4.0 packaging\windows\SentinelVision.iss
; Output: dist\installer\SentinelVision-<version>-Setup.exe
;
; Always installs into Program Files (asks for administrator permission once), so programs running as the user can
; never replace Sentinel Vision's files, and installs the "Sentinel Vision Protection" service.
; An older per-user installation (0.3.x, in the user's own folder) is removed and its data carried over.
;
; Command-line switches understood by the installer (besides Inno's /SILENT, /VERYSILENT):
;   /TASKS="autostart,desktopicon,addtopath"   choose options in silent installs
;   /RELAUNCH=1                                start the app after a silent install
;   /SERVICEUPDATE=1                           update run by the protection service (no user steps; the service's
;                                              watchdog starts the app again for signed-in users)

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
#define SvcExe "sentinel-vision-service.exe"
#define SvcName "SentinelVisionService"
#define AppIdStr "{9D3C2B71-6A4E-4F0B-9E57-2C1A8D4B5E60}"
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
; Program Files only: a folder other programs can write to would let malware replace Sentinel Vision's files
DisableDirPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
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
Name: "autostart"; Description: "Start Sentinel Vision when I sign in and restart it if it is closed (recommended)"; GroupDescription: "Protection:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add the sentinel-vision-cli command-line tool to PATH"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "migrate-user-install.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[InstallDelete]
; remove files of the previous version so stale libraries never mix with new ones
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Open-source antimalware"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent runasoriginaluser
Filename: "{app}\{#AppExe}"; Flags: nowait runasoriginaluser; Check: RelaunchRequested

[UninstallRun]
; machine-wide blocking (hosts file, firewall), then the service, then the user's decoys and start-at-sign-in
Filename: "{app}\{#SvcExe}"; Parameters: "remove-system"; Flags: runhidden waituntilterminated; RunOnceId: "SVSystem"
Filename: "{sys}\sc.exe"; Parameters: "delete {#SvcName}"; Flags: runhidden waituntilterminated; RunOnceId: "SVDeleteService"
Filename: "{app}\{#CliExe}"; Parameters: "uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "SVCleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"
; plugins an administrator added (upgrades keep them; uninstalling removes them)
Type: filesandordirs; Name: "{app}\plugins"

[Code]
const
  EnvKeyUser = 'Environment';
  EnvKeyMachine = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function RelaunchRequested(): Boolean;
begin
  Result := WizardSilent() and (ExpandConstant('{param:RELAUNCH|0}') = '1');
end;

procedure KillImage(const Image: String; const Tree: Boolean);
var
  ResultCode, I: Integer;
  Args: String;
begin
  { taskkill exits with 128 once no process with that image name is left; keep going until then. }
  Args := '/F /IM ' + Image;
  if Tree then
    Args := '/F /T /IM ' + Image;
  for I := 1 to 40 do
  begin
    if not Exec(ExpandConstant('{sys}\taskkill.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      exit;
    if ResultCode = 128 then
      exit;
    Sleep(500);
  end;
end;

function ScExec(const Params: String): Integer;
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := ResultCode
  else
    Result := -1;
end;

function ServiceExists(): Boolean;
begin
  Result := ScExec('query {#SvcName}') = 0;
end;

procedure StopService();
var
  I, ResultCode: Integer;
begin
  if not ServiceExists() then
    exit;
  ScExec('stop {#SvcName}');
  { wait until it has really stopped (its files are in use until then) }
  for I := 1 to 60 do
  begin
    Exec(ExpandConstant('{cmd}'), '/C sc.exe query {#SvcName} | find "STOPPED"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode = 0 then
      break;
    Sleep(500);
  end;
  { never its children: during an update started by the service, this installer is one of them }
  KillImage('{#SvcExe}', False);
end;

procedure StopRunningApp();
begin
  { The service would restart the app, so it goes first. The app keeps running in the tray, so a normal close
    request would only hide it: end it so files can be replaced. }
  StopService();
  KillImage('{#AppExe}', True);
  KillImage('{#CliExe}', True);
  Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if CompareText(ExtractFilePath(RemoveBackslash(WizardDirValue())), AddBackslash(ExpandConstant('{autopf}'))) <> 0 then
  begin
    Result := 'Sentinel Vision must be installed in ' + ExpandConstant('{autopf}') + ' so other programs cannot change its files.';
    exit;
  end;
  StopRunningApp();
end;

procedure InstallService();
var
  Bin: String;
begin
  Bin := '"\"' + ExpandConstant('{app}\{#SvcExe}') + '\""';
  if ServiceExists() then
    ScExec('config {#SvcName} binPath= ' + Bin + ' start= auto obj= LocalSystem DisplayName= "Sentinel Vision Protection"')
  else
    ScExec('create {#SvcName} binPath= ' + Bin + ' start= auto obj= LocalSystem DisplayName= "Sentinel Vision Protection"');
  ScExec('description {#SvcName} "Protects Sentinel Vision''s rollback vault, quarantine and settings from other programs, keeps the app running, and applies system-wide website and network blocking."');
  { restart automatically if it ever stops unexpectedly }
  ScExec('failure {#SvcName} reset= 86400 actions= restart/5000/restart/10000/restart/60000');
  ScExec('failureflag {#SvcName} 1');
  ScExec('start {#SvcName}');
end;

procedure WaitForService();
var
  I, ResultCode: Integer;
begin
  for I := 1 to 40 do
  begin
    Exec(ExpandConstant('{cmd}'), '/C sc.exe query {#SvcName} | find "RUNNING"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode = 0 then
      break;
    Sleep(500);
  end;
  Sleep(1500);
end;

var
  HadUserInstall: Boolean;

function ServiceUpdate(): Boolean;
begin
  Result := WizardSilent() and (ExpandConstant('{param:SERVICEUPDATE|0}') = '1');
end;

function InitializeSetup(): Boolean;
begin
  { an older version installed in this user's own folder (only visible here when the same user approved the prompt;
    otherwise the clean-up script, which runs as the original user, still finds it) }
  HadUserInstall := RegKeyExists(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppIdStr}_is1');
  Result := True;
end;

procedure MigrateUserInstall();
var
  ResultCode: Integer;
begin
  { runs as the ORIGINAL (not elevated) user: removes the old per-user copy, its shortcuts and PATH entry, keeps
    the start-at-sign-in choice. Nothing in the old, user-writable folder is ever run. }
  ExecAsOriginalUser(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\tools\migrate-user-install.ps1') +
    '" -NewDir "' + ExpandConstant('{app}') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log(Format('per-user install clean-up exit code %d', [ResultCode]));
  { Setup named this entry "(All users)" because the per-user one still existed; that one is gone now }
  if not RegKeyExists(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppIdStr}_is1') then
    RegWriteStringValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppIdStr}_is1',
      'DisplayName', '{#AppName}');
end;

procedure SetAutostart(const On: Boolean);
var
  ResultCode: Integer;
  Arg: String;
begin
  if On then Arg := 'autostart on' else Arg := 'autostart off';
  { run with the installer's administrator approval (the same account that approved it), so turning it off is
    accepted by the protection service too }
  Exec(ExpandConstant('{app}\{#CliExe}'), Arg, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
    { versions before 0.4 wrote a machine-wide start-at-sign-in value; the app now keeps a per-user one }
    RegDeleteValue(HKEY_LOCAL_MACHINE, '{#RunKey}', '{#RunValue}');
    { an update run by the protection service (as SYSTEM) has no signed-in user: per-user steps are skipped, and
      each user's start-at-sign-in choice stays as it is }
    if not ServiceUpdate() then
      MigrateUserInstall();
    InstallService();
    WaitForService();
    { an upgrade from a per-user install keeps that user's own start-at-sign-in choice (handled by the clean-up) }
    if not HadUserInstall and not ServiceUpdate() then
      SetAutostart(WizardIsTaskSelected('autostart'));
  end;
end;

{ ---------- uninstall ---------- }

function InitializeUninstall(): Boolean;
begin
  StopRunningApp();
  Result := True;
end;

var
  DeleteData: Boolean;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveFromPath(ExpandConstant('{app}'));
    { the app itself may have written the per-user value from its Protection page }
    RegDeleteValue(HKEY_CURRENT_USER, '{#RunKey}', '{#RunValue}');
    RegDeleteValue(HKEY_LOCAL_MACHINE, '{#RunKey}', '{#RunValue}');
    DeleteData := False;
    if not UninstallSilent() then
      DeleteData := MsgBox('Also delete Sentinel Vision''s data?' + #13#10#13#10 +
                'This includes settings, detection history, downloaded definitions, the encrypted quarantine and the ' +
                'rollback vault (encrypted earlier versions of documents) of every account on this computer. ' +
                'Your own documents are not affected.' + #13#10#13#10 +
                'Choose No to keep it for a future reinstall.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
    if DeleteData then
      Exec(ExpandConstant('{app}\{#SvcExe}'), 'wipe-data', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\SentinelVision');
    if DeleteData and DirExists(DataDir) then
      DelTree(DataDir, True, True, True);
  end;
end;
