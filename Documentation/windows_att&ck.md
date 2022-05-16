### Execution	
#### Command and Scripting Interpreter
|ID|ProcessName|Describe|
|--|--|--|
|T1059.001|powershell|--|
|T1059.003|cmd|--|
|T1059.005|wscript-vbs|--|
|T1059.006|python|--|
|T1059.007|wscript-js|--|
### Defense Evasion
#### Modify register
|ID|RegisterName|Describe|
|--|--|--|
|T1112|"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"<br>"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"<br>"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"<br>"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"|HKEY_LOCAL_MACHINE <br> HKEY_CURRENT_USER|
|T1112|"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"|--|
|T1112|"HKLM\SYSTEM\CurrentControlSet\Control\Terminal"|--|
|T1112|"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls"|--|
|T1112|"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security"|--|
|T1112|"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"|--|
|T1112|"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest"|--|
|T1112|"HKCU\Environment"|--|
|T1112|"HKCU\Software\Microsoft\Internet Explorer\ PhishingFilter\"|--|
|T1112|"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"|--|
|T1112|"HKLM\SYSTEM\CurrentControlSet\Control\Session Manage"|--|

### Impact
#### Inhibit System Recovery
|ID|ToolsRun|Describe|
|--|--|--|
|T1490|vssadmin delete shadows /all /quiet|--|
|T1490|wmic shadowcopy delete /nointeractive|--|
|T1490|wbadmin.exe delete catalog -quiet|--|
|T1490|bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no|--|
|T1490|Get-CimInstanceWin32_ShadowCopy\|Remove-CimInstance|--|
|T1490|C:WindowsSysnativevssadmin.exe"Delete Shadows /All /Quiet|--|


