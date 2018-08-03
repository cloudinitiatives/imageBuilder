#############################################################################################################
# Script Name: imageBuilder
# Author(s): Stephen Kalapati
# Company: Boeing
# Description: 2012 (GUI) Server Image Builder
# Date Last Modified: 10-08-2013
#
#############################################################################################################
$date = get-date -format "yyyyMMdd"
### VERSION CONTROL ###
$scriptVersion = "1.4"
$build = $date + "." + $scriptVersion

### 1.4 beta
	#Change source path for installation to avoid errors - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Servicing 261 untested
	#Will only run as local Administrator

### 1.3
	#Command prompt shortcut placed to the desktop in All Users profile. - SK 115
	#Turn off UAC - SK 253
	#SMB Settings to allow downlevel SMB drive maping. 256
	#Delete the _2012 Folder.
### 1.2 
	#Added version control to script and changed BUILD versioning to include script version as well. -SK
### 1.1
	#Added registry entry to include a build defined by the current date. -SK
### 1.0
	#Initial build - SK

#Import Commadlets
# None

#Define Credentials
#$Cred = get-credential

#Define Error Handleing
$ErrorActionPreference = "SilentlyContinue"

### Set Powershell to unrestricted
### Set-ExecutionPolicy -ExecutionPolicy Unrestricted

### Variables
$Owner = "lab server"

### Development Use.
#Copy-Item \\10.7.99.10\project_share\Boeing\imageBuilder\_2012 c:\ -Recurse

### Begin Script
$userName = $env:USERNAME
if ($userName -ne "Administrator")
{
Write-Host "Script must be run as local Administrator"
Exit
}
### Check OS Caption.
$OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
if ($OS -match "Server 2012")
{
### Sets the CD Drive to Z:\
Write-Host "Setting CD to Z:\  Volume 0"
#diskpart.exe /s "$env:systemdrive\windows\system32\CDtoZ.txt"
(Get-WmiObject Win32_cdromdrive).drive | %{$a = mountvol $_ /l;mountvol $_ /d;$a = $a.Trim();mountvol z: $a}

### Setting TimeZone to "UTC".
Write-Host "Setting TimeZone to UTC".
tzutil /s "UTC"

### Take file Ownership From Trusted Installer.
Write-Host "Take file Ownership From Trusted Installer."
#takeown /f "$env:systemdrive\windows\system32\defrag.exe"
takeown /f "$env:systemdrive\windows\resources\ease of access themes\basic.theme"
takeown /f "$env:systemdrive\windows\web\wallpaper\windows\*"
takeown /f "$env:systemdrive\windows\web\screen\*"

### Get and Set ACL's.
Write-Host "Get and Set ACL's."
$File01 = Get-Acl "$env:systemdrive\windows\Resources\ease of access themes\basic.theme"
$File02 = Get-Acl "$env:systemdrive\windows\Web\Wallpaper\Windows\img0.jpg"
$File03 = Get-Acl "$env:systemdrive\windows\web\screen\img100.png"
icacls "$env:systemdrive\windows\resources\ease of access themes\basic.theme" /grant Administrator:f
#icacls "$env:systemdrive\windows\web\wallpaper\windows\img0.jpg" /grant Administrator:f
icacls "$env:systemdrive\windows\web\screen\img101.jpg" /grant Administrator:f
icacls "$env:systemdrive\windows\web\screen\img102.png" /grant Administrator:f
icacls "$env:systemdrive\windows\web\screen\img103.jpg" /grant Administrator:f
icacls "$env:systemdrive\windows\web\screen\img104.jpg" /grant Administrator:f
icacls "$env:systemdrive\windows\web\screen\img105.jpg" /grant Administrator:f

### Set Firewall Rules.
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

### Remove unecessary files to reduce size footprint.
Write-Host "Remove unecessary files to reduce size footprint."
Remove-Item -Path "$env:systemdrive\windows\*.bmp" -recurse
Remove-Item -Path "$env:systemdrive\windows\Resources\ease of access themes\basic.theme" -recurse
Remove-Item -Path "$env:systemdrive\windows\web\screen\img101.*" -recurse
Remove-Item -Path "$env:systemdrive\windows\web\screen\img102.*" -recurse
Remove-Item -Path "$env:systemdrive\windows\web\screen\img103.*" -recurse
Remove-Item -Path "$env:systemdrive\windows\web\screen\img104.*" -recurse
Remove-Item -Path "$env:systemdrive\windows\web\screen\img105.*" -recurse
#Remove-Item -Path "$env:systemdrive\windows\web\wallpaper\*.jpg" -recurse
#Remove-Item -Path "$env:systemdrive\windows\web\wallpaper\*.bmp" -recurse
#Remove-Item -Path "$env:systemdrive\windows\web\wallpaper\Windows\*.jpg" -recurse
#Remove-Item -Path "$env:systemdrive\windows\web\wallpaper\Windows\*.bmp" -recurse
Remove-Item -Path "$env:systemdrive\Users\Public\Documents\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Public\Desktop\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Default\Desktop\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Default\Documents\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Default\Favorites\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Default\Pictures\*" -recurse
Remove-Item -Path "$env:systemdrive\Users\Default\Music\*" -recurse

### Create Directories.
Write-Host "Creating Directories"
New-Item -type directory -path "$env:systemdrive\BGinfo"
#New-Item -type directory -path "$env:systemdrive\windows\system32\oobe\info"
#New-Item -type directory -path "$env:systemdrive\windows\system32\oobe\info\backgrounds"

### Copy Files.
Write-Host "Copying Files..."
Copy-Item "$env:systemdrive\_2012\bin\BGInfo\*" "$env:systemdrive\bginfo" -recurse
Copy-Item "$env:systemdrive\_2012\bin\windowsroot\*" "$env:systemdrive\windows" -recurse
Copy-Item "$env:systemdrive\_2012\bin\themes\*" "$env:systemdrive\windows\resources\ease of access themes\" -recurse
Copy-Item "$env:systemdrive\_2012\bin\system32\*" "$env:systemdrive\windows\system32\" -recurse
Copy-Item "$env:systemdrive\_2012\bin\startup\*" "$env:systemdrive\documents and settings\all users\start menu\programs\startup\" -recurse
Copy-Item "$env:systemdrive\_2012\bin\shortcuts\cmd.lnk" "$env:AllUsersProfile\Desktop" -recurse
C:\Windows\System32
#Copy-Item "$env:systemdrive\_2012\bin\logonui\*" "$env:systemdrive\windows\web\screen\" -recurse

### Restore TrustedInstaller
Write-Host "Restoring TrustedInstaller"
#icacls "$env:systemdrive\windows\resources\ease of access themes\basic.theme" /setowner "NT Service\TrustedInstaller" /T /C
#icacls "$env:systemdrive\windows\web\wallpaper\windows\*" /setowner "NT Service\TrustedInstaller" /T /C
#icacls "$env:systemdrive\windows\web\screen\*" /setowner "NT Service\TrustedInstaller" /T /C
Set-Acl "$env:systemdrive\windows\Resources\Ease of Access Themes\basic.theme" $File01
#Set-Acl "$env:systemdrive\windows\Web\Wallpaper\Windows\img0.jpg" $File02
#Set-Acl "$env:systemdrive\windows\web\screen\img100.png" $File03


### Create a Profile to Facilitate Deleting the Current Administrator's Profile.
Write-Host "Creating profile1 user to facilitate deleting the current Administrator profile"
net user profile1 p@ssw0rd /ADD
net localgroup Administrators profile1 /ADD

### Set Service Startup.
Write-Host "Optimizing System Services"
	# Name: Certificate Propagation.
	# Default: Manual.
	Set-Service CertPropSvc -StartupType Disabled

	# Name: IP Helper.
	# Default: Automatic.
	Set-Service iphlpsvc -StartupType Disabled

	# Name: Print Spooler.
	# Default: Automatic.
	Set-Service Spooler -StartupType Disabled

	# Name: Remote Procedure Call (RPC) Locator.
	# Default: Manual.
	Set-Service RpcLocator -StartupType Disabled

	# Name: Smart Card.
	# Default: Manual.
	Set-Service SCardSvr -StartupType Disabled

	# Name: Smart Card Removal Policy.
	# Default: Manual.
	Set-Service SCPolicySvc -StartupType Disabled

	# Name: Themes Services.
	# Default: Automatic.
	Set-Service Themes -StartupType Disabled

	# Name: Windows Audio.
	# Default: Manual.
	Set-Service AudioSrv -StartupType Disabled

	# Name: Windows Audio Endpoint Builder.
	# Default: Manual.
	Set-Service AudioEndpointBuilder -StartupType Disabled

	# Name: Windows Color System.
	# Default: Manual.
	Set-Service WcsPlugInService -StartupType Disabled

	# Name: Windows Error Reporting Service.
	# Default: Manual.
	Set-Service WerSvc -StartupType Disabled

	# Name: Windows Font Cache Service.
	# Default: Manual.
	Set-Service FontCache -StartupType Disabled

### Registry and System Modifications.

	# Disable Windows Error Reporting.
	Write-Host "Disabling Windows Error Reporting"
	Disable-WindowsErrorReporting

	# Mounts C:\Documents and Settings\Default User\NTUSER.DAT into registry as HKLM\NTUSER.
	reg load HKLM\NTUSER "C:\Users\Default\ntuser.dat"

	# Disable the Server Manager.
	Set-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\ServerManager" -Name InitializationComplete -Value 1 -force
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon  -PropertyType DWord -Value 1

	# Disables the Recycle Bin
	#New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name Explorer -Force
	#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -PropertyType DWord -Value 95 -Force
	#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRecycleFiles -PropertyType DWord -Value 1 -Force
	
	New-Item -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies" -Name Explorer -Force
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -PropertyType DWord -Value 95 -Force
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRecycleFiles -PropertyType DWord -Value 1 -Force
	
	# Do Not Display Last User Name. (Security)
	New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -PropertyType DWord -Value 1 -Force
	
	# Set Owner Info
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name RegisteredOrganization -PropertyType String -Value $Owner -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name RegisteredOwner -PropertyType String -Value $Owner -Force
	
	# Set "Adjust for best performance"
	New-Item -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name VisualEffects -Force
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -PropertyType DWord -Value 2 -Force
	
	# Set Secure Screen Saver.
	New-ItemProperty -Path "HKLM:\NTUSER\Control Panel\Desktop" -Name ScreenSaveTimeOut -PropertyType String -Value 600 -Force
	New-ItemProperty -Path "HKLM:\NTUSER\Control Panel\Desktop" -Name ScreenSaverIsSecure -PropertyType String -Value 1 -Force
	
	# Classic Control Panel.
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name ForceClassicControlPanel -PropertyType DWord -Value 1 -Force
	
	# Hide the Volume on Taskbar.
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HideSCAVolume -PropertyType DWord -Value 1 -Force
	
	# Hide the Clock. (Disabled)
	#New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HideClock -PropertyType DWord -Value 1 -Force
	
	# Small Taskbar
	New-ItemProperty -Path "HKLM:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarSmallIcons -PropertyType DWord -Value 1 -Force
	
	# Show All Control Panel Icons (SMALL)
	New-Item -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name ControlPanel -Force
	New-ItemProperty -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name AllItemsIconView -PropertyType DWord -Value 1 -Force
	
	# Show "Computer" Icon on Desktop
	New-Item -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name HideDesktopIcons -Force
	New-Item -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name NewStartPanel -Force
	New-ItemProperty -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0 -Force
	
	# Desktop ICON Resize (SMALL)
	New-Item -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion" -Name RunOnce -Force
	New-ItemProperty -Path "HKLM:NTUSER\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name DesktopIconResize -PropertyType String -Value "C:\Windows\DesktopIconSize.exe -4" -Force
	
	# Allow Remote Desktop
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -PropertyType DWord -Value 0 -Force
	
	# Tag Build Number into registry
	New-ItemProperty -Path "HKLM:System\Setup" -Name ImageBuild -PropertyType String -Value "$build" -Force

	# Disables UAC
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
	
	# Allow downlevel SMB mappings
	Set-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters” RequireSecureNegotiate -Value 0 -Force
	
	#Set LocalSourcePath
	New-Item -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies" -Name Servicing -Force
	New-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Servicing" -Name LocalSourcePath -PropertyType String -Value "Z:\" -Force
	
	# UnMounts C:\Documents and Settings\Default User\NTUSER.DAT from the registry.
	cd c:\ # First we need to change the drive to release the lock on the registry.
	Write-Host "Unloading the Registry Hive. Please Wait"
	[gc]::collect()
	Start-Sleep 2
	reg unload HKLM\NTUSER # Unload the registry Hive
	
### Final Cleanup
Write-Host "Final Cleanup"
Remove-Item -Path "$env:systemdrive\_2012" -recurse
	
### Reboot the Server
shutdown -r -t 3
}
Else
{
Write-Host "Windows Server 2012 Not Detected.  Exiting..."
}