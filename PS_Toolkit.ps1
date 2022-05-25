# PS Toolkit

<#
.SYNOPSIS
    Functions and tools for Windows PC troubleshooting
.DESCRIPTION
    Series of functions intended to make desktop support and basic system troubleshooting easier, and to put some pre-existing tools in one convenient location for quick access.
    Divided into General Functions (generic tools, user-profile and various caches cleanup, file system scans, network maintenance), Windows OS Maintenance (mostly just repackaged DISM commands),
    and Hardware Maintenance for things like power, RAM, and drives.
.NOTES
    I chose to query user instead of using CIM to get the signed-in username because CIM returns null for RDP users while query user does not.
    The function to re-register all UWP apps for the current user works fine, but the output from that command stays in the console even after a Clear-Host command.
    I don't know why or how to avoid this, so for now I've just made the shell quit after that command. If running multiple commands, maybe do that one last; otherwise just re-launch the script.
    A big part of the reason I wrote this is to learn PowerShell, so suggestions are certainly welcome.
    Please let me know if anything breaks or doesn't work the way you expect it to. I want this to be effective and intuitive!
    And of course let me know if you think anything should be added/removed/changed, etc.
    v6.3.5
#>


# Prompt for Administrator rights
#/======================================================================================/
# Check if the shell is running as Administrator. If not, call itself with "Run as
# Admin", then quit
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
#//====================================================================================//


# Gather System Info
#/======================================================================================/
Write-Host "Loading system information. Please wait . . ."

$script:UserName = ((query user | findstr 'Active').split('>')[1]).split('')[0]
$script:User = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$script:OSbuild = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
$script:HostName = hostname
$script:PCModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$script:SvcTag = (Get-WmiObject -ClassName Win32_SystemEnclosure).SerialNumber
$script:Boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$script:IPOrigin = (Get-NetIPAddress -AddressFamily IPv4).PrefixOrigin | Select-Object -First 1
$script:IPv4 = (Get-NetIPAddress -AddressFamily IPv4).IPAddress | Select-Object -First 1
$script:IPGate = ((Get-NetIPConfiguration).IPv4DefaultGateway).NextHop
$script:DiskMan = (Get-Disk -Number 0).Manufacturer
$script:DiskMod = (Get-Disk -Number 0).Model
$script:DiskStat = (Get-Disk -Number 0).HealthStatus
$Power = (Get-CimInstance -ClassName Win32_ComputerSystem).PowerSupplyState

# Change "Dhcp" to "DHCP" (purely aesthetic)
if ($IPOrigin -eq 'Dhcp') {
    $script:IPOrigin = 'DHCP'
}

# The CIM query for PowerSupplyState returns a number; the associated PSU states are defined here:
# https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
if ($Power -eq 1) {
    $script:Power = 'Other'
}
elseif ($Power -eq 2) {
    $script:Power = 'Unknown'
}
elseif ($Power -eq 3) {
    $script:Power = 'Safe'
}
elseif ($Power -eq 4) {
    $script:Power = 'Warning'
}
elseif ($Power -eq 5) {
    $script:Power = 'Critical'
}
elseif ($Power -eq 6) {
    $script:Power = 'Non-recoverable'
}
else {
    $script:Power = 'No data'
}

# Match OS build number to Version
if ($OSbuild -like '*18363*') {
    $script:OSver = '1909'
}
elseif ($OSbuild -like '*19041*') {
    $script:OSver = '2004'
}
elseif ($OSbuild -like '*19042*') {
    $script:OSver = '20H2'
}
elseif ($OSbuild -like '*19043*') {
    $script:OSver = '21H1'
}
elseif ($OSbuild -like '*19044*') {
    $script:OSver = '21H2'

}
else {
    $script:OSver = 'No data'
}

# Display Main Menu
#/======================================================================================/
function Show-Menu
{
    Clear-Host
    Write-Host "General Functions                                                  System Info                              v6.3.5"
    Write-Host "=======================================================            ================================="
    Write-Host " 1. View chronological Stability Index                             Hostname:        $HostName"
    Write-Host " 2. Reset Windows Update                                           OS Version:      $OSver"
    Write-Host " 3. Reset network settings                                         OS Build:        $OSbuild"
    Write-Host " 4. Detect and repair file system errors                           Model:           $PCModel"
    Write-Host " 5. Get results of most recent file system check                   Service Tag:     $SvcTag"
    Write-Host " 6. Clear Offline Files client-side cache for all users            Last Boot:       $Boot"
    Write-Host " 7. Clear credential cache for signed-in user                      IPv4 Address:    $IPv4"
    Write-Host " 8. Clear Edge cache for signed-in user                            Address Origin:  $IPOrigin"
    Write-Host " 9. Clear Teams cache for signed-in user                           Default Gateway: $IPGate"
    Write-Host "10. Re-register all UWP apps for signed-in user                    Drive Model:     $DiskMan$DiskMod" 
    Write-Host "11. Remove System-level Chrome                                     Drive Status:    $DiskStat"
    Write-Host "12. Back up BitLocker recovery key to AD                           PSU Status:      $Power"   
    Write-Host "13. Enable BitLocker (and back up recovery key)"                                               
    Write-Host "14. List and remove local Windows profiles"
    Write-Host ""
    Write-Host "Windows OS Maintenance"
    Write-Host "======================================================="
    Write-Host "15. Check the component store log for errors"
    Write-Host "16. Scan the component store to detect errors"
    Write-Host "17. Rebuild the component store from Windows Update"
    Write-Host "18. Check Windows OS files and repair errors"
    Write-Host ""
    Write-Host "Hardware Maintenance"
    Write-Host "======================================================="
    Write-Host "19. Run memory diagnostic"
    Write-Host "20. Get results of most recent memory diagnostic"
    Write-Host "21. Get system power report"
    Write-Host "22. Get battery report (laptop only)"
    Write-Host "23. Get device installation log"
    Write-Host "24. Open Drive Optimizer"
    Write-Host ""
    Write-Host " 0. Reboot    P. New PS prompt    X. Exit"
    Write-Host ""
}
#//====================================================================================//


# Prompt to show at the end of each function
#/======================================================================================/
function Show-End
{
    Write-Host ""
    Write-Host "Operation complete."
    Write-Host "Press any key to return to the menu."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-Menu
}
#//====================================================================================//


# [1] View chronological Stability Index
#/======================================================================================/
function Start-RelMon
{
    Clear-Host
    Write-Host "Reliability Monitor is starting. Please wait . . ."

    Start-Process perfmon.exe -ArgumentList "/rel"
    Start-Sleep -Seconds 3
}
#//====================================================================================//


# [2] Reset Windows Update
#/======================================================================================/
function Reset-Update
{
    Clear-Host
    Write-Host "Stopping Windows Update process and services . . ."

    Stop-Service -Name BITS
    Stop-Service -Name CryptSvc
    Stop-Service -Name wuauserv

    # Delete BITS queue and any Windows Update backup folders; create new backups
    Remove-Item -Path "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.*"
    Remove-Item -Path "$env:SYSTEMROOT\SoftwareDistribution.bak" -Recurse
    Remove-Item -Path "$env:SYSTEMROOT\System32\catroot2.bak" -Recurse

    Rename-Item -Path "$env:SYSTEMROOT\SoftwareDistribution" -NewName "SoftwareDistribution.bak"
    Rename-Item -Path "$env:SYSTEMROOT\System32\catroot2" -NewName "catroot2.bak"

    # Reset BITS and wuauserv security descriptors
    sc.exe sdset bits --% D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
    sc.exe sdset wuauserv --% D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) 
   
    # Reregister DLLs
    Start-Process regsvr32.exe -ArgumentList "/s atl.dll"
    Start-Process regsvr32.exe -ArgumentList "/s urlmon.dll"
    Start-Process regsvr32.exe -ArgumentList "/s mshtml.dll"
    Start-Process regsvr32.exe -ArgumentList "/s shdocvw.dll"
    Start-Process regsvr32.exe -ArgumentList "/s browseui.dll"
    Start-Process regsvr32.exe -ArgumentList "/s jscript.dll"
    Start-Process regsvr32.exe -ArgumentList "/s vbscript.dll"
    Start-Process regsvr32.exe -ArgumentList "/s scrrun.dll"
    Start-Process regsvr32.exe -ArgumentList "/s msxml.dll"
    Start-Process regsvr32.exe -ArgumentList "/s msxml3.dll"
    Start-Process regsvr32.exe -ArgumentList "/s msxml6.dll"
    Start-Process regsvr32.exe -ArgumentList "/s actxprxy.dll"
    Start-Process regsvr32.exe -ArgumentList "/s softpub.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wintrust.dll"
    Start-Process regsvr32.exe -ArgumentList "/s dssenh.dll"
    Start-Process regsvr32.exe -ArgumentList "/s rsaenh.dll"
    Start-Process regsvr32.exe -ArgumentList "/s gpkcsp.dll"
    Start-Process regsvr32.exe -ArgumentList "/s sccbase.dll"
    Start-Process regsvr32.exe -ArgumentList "/s slbcsp.dll"
    Start-Process regsvr32.exe -ArgumentList "/s cryptdlg.dll"
    Start-Process regsvr32.exe -ArgumentList "/s oleaut32.dll"
    Start-Process regsvr32.exe -ArgumentList "/s ole32.dll"
    Start-Process regsvr32.exe -ArgumentList "/s shell32.dll"
    Start-Process regsvr32.exe -ArgumentList "/s initpki.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wuapi.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wuaueng.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wuaueng1.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wucltui.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wups.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wups2.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wuweb.dll"
    Start-Process regsvr32.exe -ArgumentList "/s qmgr.dll"
    Start-Process regsvr32.exe -ArgumentList "/s qmgrprxy.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wucltux.dll"
    Start-Process regsvr32.exe -ArgumentList "/s muweb.dll"
    Start-Process regsvr32.exe -ArgumentList "/s wuwebv.dll"

    # Reset proxy and winsock -
    netsh.exe winsock reset
    netsh.exe winhttp reset proxy

    # Restart services 
    Start-Service -Name BITS
    Start-Service -Name CryptSvc
    Start-Service -Name wuauserv
    Start-Process sc.exe -ArgumentList "config bits start= delayed-auto"
    Start-Process sc.exe -ArgumentList "config cryptsvc start= auto"
    Start-Process sc.exe -ArgumentList "config wuauserv start= demand"

    # End operation
    Clear-Host
    Write-Host ""
    Write-Host "You must restart the computer to complete this operation."
    
    $UpdateEnd = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
    switch ($UpdateEnd)
    {
        Y {Restart-PC}
        N {Show-Menu}        
    }
}
#//====================================================================================//


# [3] Reset network settings
#/======================================================================================/
function Reset-NetSet
{
    Clear-Host

    # Function to show final reboot prompt
    # /-----------------------------------------------------------/
    function Show-NetEnd
    {
        Show-Header

        Write-Host 'You must restart the computer to complete this operation.'
        Write-Host ''

        $NetEnd = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
        switch ($NetEnd)
        {
            Y {Restart-PC}
            N {Show-Menu}
        }
    }
    # //---------------------------------------------------------//


    # Function to delete NIC configuration data
    # /-----------------------------------------------------------/
    function Remove-NetCfg
    {
        netcfg.exe -d
        Show-NetEnd
    }
    # //---------------------------------------------------------//


    # Main NetSet routine
    # /-----------------------------------------------------------/
    $AdvProps = (Get-NetAdapterAdvancedProperty).DisplayName
    $Adapter = (Get-NetAdapter).Name

    Remove-NetIPAddress -Confirm:$false 2> $null
    Clear-DnsClientCache
    netsh.exe winsock reset
    netsh.exe int ip reset
    netsh.exe int tcp reset
    Reset-NetAdapterAdvancedProperty -DisplayName $AdvProps
    Restart-NetAdapter -Name $Adapter

    Write-Host 'Note: Before deleting configuration data, ensure you have the means to reinstall the devices!' -ForegroundColor Yellow
    $NICdel = Read-Host -Prompt 'Would you like to delete configuration data for all network devices? (Y/N)'
    switch ($NICdel)
    {
        Y {Remove-NetCfg}
        N {Show-NetEnd}
    }
    # //---------------------------------------------------------//
}
#//====================================================================================//


# [4] Detect and repair file system errors
#/======================================================================================/
function Start-ChkdskF
{
    Clear-Host

    chkdsk.exe /f
    
    # See if we need to reboot with chkntfs. If yes, show prompt. Otherwise go back to menu
    $Dirty = chkntfs.exe c:

    if ($Dirty -like '*not*') {
        Show-Menu
    } else {
        Write-Host ""
        $ChkdskEnd = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
        switch ($ChkdskEnd)
        {
            Y {Restart-PC}
            N {Show-Menu}        
        } 
    }
}
#//====================================================================================//


# [5] Get results of most recent file system check
#/======================================================================================/
function Get-ChkdskRes
{
    Clear-Host

    # Get info from event log
    $ChkdskMessage = Get-EventLog -LogName Application -Source Wininit |
        Where-Object {$_.Message -like '*checking file system*'} |
        Sort-Object TimeGenerated -Descending |
        Select-Object -First 1 -ExpandProperty Message
    $ChkdskResult = $ChkdskMessage -split "`n" | 
        Select-String -Pattern 'Windows' | 
        Select-Object -Last 1
    $ChkdskEvent = Get-EventLog -LogName Application -Source Wininit |
        Where-Object {$_.Message -like '*checking file system*'} |
        Sort-Object TimeGenerated -Descending |
        Select-Object -First 1 -Property EventID,TimeGenerated
    $ChkdskID = $ChkdskEvent.EventID
    $ChkdskTime = $ChkdskEvent.TimeGenerated
    
    # If event exists, display info. Otherwise prompt to run Chkdsk
    if ($ChkdskEvent) {        
        Write-Host "Channel:        Application"
        Write-Host "Source:         Microsoft-Windows-Wininit"
        Write-Host "EventID:        $ChkdskID"
        Write-Host "TimeCreated:    $ChkdskTime"
        Write-Host "Message:        $ChkdskResult"
        Show-End
    } else {
        Clear-Host
        Write-Host ""
        Write-Host "No results found."
        Write-Host ""
        $NoEvent = Read-Host -Prompt 'Would you like to perform a check of the file system? (Y/N)'
    }
    
    switch ($NoEvent)
    {
        Y {Start-ChkdskF}
        N {Show-Menu}
    }
}
#//====================================================================================//


# [6] Clear Offline Files Client-Side-Cache for all users
#/======================================================================================/
function Clear-CSC
{
    Clear-Host

    $CSCKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CSC\Parameters"

    if (Test-Path $CSCKey) {
        New-ItemProperty -Path $CSCKey -Name FormatDatabase -PropertyType Dword -Value 1 -Force
    } else {
        New-Item -Path $CSCKey
        New-ItemProperty -Path $CSCKey -Name FormatDatabase -PropertyType Dword -Value 1 -Force
    }

    Write-Host "CSC parameter has been adjusted."
    Write-Host "You must restart the computer to complete this operation."
    $CSCend = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
    switch ($CSCend)
    {
        Y {Restart-PC}
        N {Show-Menu}        
    }
}
#//====================================================================================//


# [7] Clear credential cache for signed-in user
#/======================================================================================/
function Clear-CredMan
{
    Clear-Host

    # Create self-deleting CredMan script
    New-Item -Path "C:\" -Name 'Temp' -ItemType Directory -Force | Out-Null
    Set-Content -Path 'C:\Temp\CredMan_local.cmd' -Value "for /f `"tokens=1,2 delims= `" %%B in ('cmdkey /list ^| findstr Target') do cmdkey /delete %%C & del %~f0"
        
    # If Active Setup is already configured, bump the version number by 1 so it will run again; else create the new GUID
    $CredMan = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*' |
        Get-ItemProperty -Name `(Default`),Version -ErrorAction SilentlyContinue |
        Where-Object { ("$_.(Default)" -match 'Clear CredMan') }
    
    if ($CredMan) {
        Write-Host "Updating Active Setup task..."
        $CredManGUID = $CredMan.PSChildName
        $NewVersion = ($CredMan.Version -as [int]) + 1 | Out-String
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$CredManGUID" -Name 'Version' -Value "$NewVersion" -Force | Out-Null
        Write-Host "Active Setup component $CredManGUID has been updated."
        Write-Host "All Windows Credentials in the Credential Manager will be deleted at next sign-in."
    } else {
        Write-Host "Adding Active Setup task..."
        $NewGUID = New-Guid
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' -Name "{$NewGUID}" | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{$NewGUID}" -Name '(Default)' -PropertyType String -Value 'Clear CredMan' -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{$NewGUID}" -Name 'StubPath' -PropertyType String -Value 'C:\Temp\CredMan_local.cmd' -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{$NewGUID}" -Name 'Version' -PropertyType String -Value '1' -Force | Out-Null
        Write-Host "Active Setup component {$NewGUID} has been created."
        Write-Host "All Windows Credentials in the Credential Manager will be deleted at next sign-in."
    }

    Show-End
}
#//====================================================================================//


# [8] Clear Edge cache for signed-in user
#/======================================================================================/
function Clear-Edge
{
    Clear-Host
    Write-Host "Ensuring Edge is stopped . . ."
    Write-Host ""
    
    Stop-Process -Name msedge -Force 2> $null
    
    Write-Host "Clearing cached data for $User . . ."

    # Ensure Edge has enough time to stop
    Start-Sleep -Seconds 3

    Push-Location "C:\Users\$UserDir\AppData\Local\Microsoft\Edge\User Data\Default"
    Remove-Item "cookies","Login Data","Web Data","Cache","IndexedDB" -Force -Recurse 2> $null
    Pop-Location

    Show-End
}
#//====================================================================================//


# [9] Clear Teams cache for signed-in user
#/======================================================================================/
function Clear-Teams
{
    Clear-Host
    Write-Host "Ensuring Teams is stopped . . ."
    Write-Host ""

    Stop-Process -Name Teams -Force 2> $null
    
    Write-Host "Clearing cached data for $User . . ."

    # Ensure Teams has enough time to stop
    Start-Sleep -Seconds 3

    Push-Location "C:\Users\$UserDir\AppData\Roaming\Microsoft\Teams"
    Remove-Item "Cache","blob_storage","databases","GPUCache","IndexedDB","Local Storage","tmp" -Force -Recurse 2> $null
    Pop-Location

    Show-End
}
#//====================================================================================//


# [10] Re-register all UWP apps for signed-in user
#/======================================================================================/
function Reset-UwpApps
{
    Clear-Host

    Write-Host "The shell will quit when this operation is complete."
    $ResetApps = Read-Host -Prompt "Do you wish to continue? (Y/N)"
    switch ($ResetApps)
    {
        Y {
            Get-AppXPackage | ForEach-Object -Process {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
            Exit
        }
        N {Show-Menu}
    }
}
#//====================================================================================//


# [11] Remove System-level Chrome
#/======================================================================================/
function Remove-Chrome
{
    Clear-Host
    Write-Host "Uninstalling System-level Chrome . . ."
    Write-Host

    $ChromeExe = Get-ChildItem -Path "C:\Program Files\Google\Chrome\Application\Setup.exe" -Recurse

    if ($? -eq $true) {
        Start-Process $ChromeExe -ArgumentList "-uninstall -multi-install -chrome -system-level -force-uninstall"
        if ($? -ne $true) {
            Write-Host "Failed to uninstall!"
        }
    } else {
        $ChromeExe = Get-ChildItem -Path "C:\Program Files (x86)\Google\Chrome\Application\Setup.exe" -Recurse
        if ($? -eq $true) {
            Start-Process $ChromeExe -ArgumentList "-uninstall -multi-install -chrome -system-level -force-uninstall"
            if ($? -ne $true) {
                Write-Host "Failed to uninstall!"
            }
        } else {
            Write-Host "Failed to find the uninstaller!"
        }
    }

    Show-End
}
#//====================================================================================//


# [12] Back up BitLocker recovery key to Active Directory
#/======================================================================================/
function Start-BDEbak
{
    Clear-Host

    if ( (Get-BitLockerVolume -MountPoint C:).VolumeStatus -eq "FullyDecrypted") {
        Write-Host "BitLocker is not enabled!"
        Write-Host ""
        $StartBDE = Read-Host -Prompt "Would you like to enable BitLocker now? (Y/N)"
        switch ($StartBDE)
        {
            Y {Start-BDE}
            N {Show-Menu}
        }
    } else {
        Write-Host "Backing up BitLocker Recovery Key to Active Directory."
        $KeyID = ( (Get-BitLockerVolume -MountPoint C:).KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} ).KeyProtectorID
        Backup-BitLockerKeyProtector -MountPoint C: -KeyProtectorId $KeyID
        Show-End
    }
}
#//====================================================================================//


# [13] Enable BitLocker (and back up recovery key)
#/======================================================================================/
function Start-BDE
{
    Clear-Host

    if ( (Get-BitLockerVolume -MountPoint C:).VolumeStatus -ne "FullyDecrypted") {
        Write-Host "$HostName is already encrypted."
        Show-End
    } else {
        Write-Host "Enabling BitLocker..."
        Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector
        Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector
        if ($? -ne $true) {
            Write-Host "Something went wrong and BitLocker was not enabled!" -ForegroundColor Red
        } else {
            Write-Host "BitLocker is now enabled." -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "You must restart the computer to complete this operation."
        $BDEend = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
        switch ($BDEend)
        {
            Y {Restart-PC}
            N {Show-Menu}        
        }
    }
    
}
#//====================================================================================//


# [14] List and remove local Windows profiles
#/======================================================================================/
function Remove-Profile
{
    Clear-Host
    
    Write-Host "C:\Directory~\UserName"
    Write-Host "--------------------------------"
    Write-Host ""

    $Profiles = Get-CimInstance -ClassName Win32_UserProfile | Select-Object -ExpandProperty LocalPath | Out-String

    Write-Host "$Profiles"
        
    $UserSam = Read-Host -Prompt "Please enter only the UserName of the profile to remove, or X to go back"
    if ($UserSam -eq 'X') {
        Show-Menu
    } else {
        $UserProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.LocalPath -eq "C:\Users\$UserSam"}

        Clear-Host
        Write-Host "Removing profile $UserSam. This may take a moment . . ."
        Write-Host ""

        Remove-CimInstance -InputObject $UserProfile

        if ($? -ne $true) {
            if ($Error[0] -like "*process*") {
                Clear-Host
                Write-Host "Profile $UserSam is in use!"
                Write-Host "Cannot remove a profile while it is in use."
                Write-Host ""
                $InuseEnd = Read-Host -Prompt "Would you like to remove a different profile? (Y/N)"
                switch ($InuseEnd)
                {
                    Y {Remove-Profile}
                    N {Show-Menu}        
                }
            } elseif ($Error[0] -like "*null*") {
                Clear-Host
                Write-Host "Cannot find profile for $UserSam!"
                Write-Host "Verify the profile exists and try again."
                Write-Host ""
                $NullEnd = Read-Host -Prompt "Would you like to try again now? (Y/N)"
                switch ($NullEnd)
                {
                    Y {Remove-Profile}
                    N {Show-Menu}        
                }
            }
        } else {
            Write-Host "Profile $UserSam removed."
            Write-Host "The profile will be rebuilt when $UserSam signs back in."
            Write-Host ""
            $RemovedEnd = Read-Host -Prompt "Would you like to remove another profile? (Y/N)"
            switch ($RemovedEnd)
            {
                Y {Remove-Profile}
                N {Show-Menu}
            }
        }
    }
}
#//====================================================================================//


#    //===========================================================================//
#    //                                                                           //
#    //                          WINDOWS OS MAINTENANCE                           //
#    //                                                                           //
#    //===========================================================================//


# [15] Check the component store log for errors
#/======================================================================================/
function Start-DismC
{
    Clear-Host

    Repair-WindowsImage -Online -CheckHealth
    
    Show-End
}
#//====================================================================================//


# [16] Scan the component store to detect errors
#/======================================================================================/
function Start-DismS
{
    Clear-Host

    Repair-WindowsImage -Online -ScanHealth

    Show-End
}
#//====================================================================================//


# [17] Rebuild the component store from Windows Update
#/======================================================================================/
function Start-DismR
{
    Clear-Host

    Repair-WindowsImage -Online -RestoreHealth

    Show-End
}
#//====================================================================================//


# [18] Check Windows OS files and repair errors
#/======================================================================================/
function Start-SFC
{
    Clear-Host
    
    sfc.exe /scannow

    Show-End
}
#//====================================================================================//


#    //===========================================================================//
#    //                                                                           //
#    //                           HARDWARE MAINTENANCE                            //
#    //                                                                           //
#    //===========================================================================//


# [19] Run memory diagnostic
#/======================================================================================/
function Start-MemDiag
{
    Start-Process MdSched.exe
}
#//====================================================================================//


# [20] Get results of most recent memory diagnostic
#/======================================================================================/
function Get-MemRes
{
    Clear-Host

    # Get info from event log
    $MemEvent = Get-EventLog -LogName System -Source Microsoft-Windows-MemoryDiagnostics-Results |
        Sort-Object -Property TimeGenerated -Descending |
        Select-Object -First 1 -Property EventID,TimeGenerated,Message
    $MemID = $MemEvent.EventID
    $MemTime = $MemEvent.TimeGenerated
    $MemResult = $MemEvent.Message

    # If event exists, display info. Otherwise prompt to run MdSched
    if ($MemEvent) {      
        Write-Host "Channel:     System"  
        Write-Host "Source:      Microsoft-Windows-MemoryDiagnostics-Results"
        Write-Host "EventID:     $MemID"
        Write-Host "TimeCreated: $MemTime"
        Write-Host "Message:     $MemResult"
        Show-End
    } else {
        Clear-Host
        Write-Host ""
        Write-Host "No results found."
        Write-Host ""
        $NoEvent = Read-Host -Prompt 'Would you like to perform a memory diagnostic? (Y/N)'
    }

    switch ($NoEvent)
    {
        Y {Start-MemDiag}
        N {Show-Menu}
    }
}
#//====================================================================================//


# [21] Get system power report
#/======================================================================================/
function Get-PwrRep
{
    Clear-Host

    $PowerDays = Read-Host -Prompt 'Enter the number of days to query (max 28)'

    Write-Host ""
    Write-Host "Generating system power report. Please wait . . ."
    
    Start-Process powercfg.exe -ArgumentList "/systempowerreport /duration $PowerDays"
        
    Invoke-Item C:\Windows\System32\sleepstudy-report.html
}
#//====================================================================================//


# [22] Get battery report
#/======================================================================================/
function Get-BatRep
{
    Clear-Host

    $BatteryDays = Read-Host -Prompt 'Enter the number of days to query (max 28)'
    
    Write-Host ""
    Write-Host "Generating battery report. Please wait . . ."

    Start-Process powercfg.exe -ArgumentList "/batteryreport /duration $BatteryDays"
    Start-Sleep -Seconds 5

    Invoke-Item C:\Windows\System32\battery-report.html
}
#//====================================================================================//


# [23] Get device installation log
#/======================================================================================/
function Get-DevLog
{
    Invoke-Item C:\Windows\INF\setupapi.dev.log
}
#//====================================================================================//


# [24] Open Drive Optimizer
#/======================================================================================/
function Start-Dfr
{
    Start-Process dfrgui.exe
}
#//====================================================================================//


# [0] Restart the PC
#/======================================================================================/
function Restart-PC
{
    Clear-Host
    Write-Host "The system is rebooting."
    Start-Sleep -Seconds 3
    Restart-Computer
}
#//====================================================================================//


# [P] Spawn new PowerShell prompt
#/======================================================================================/
function Start-PS
{
    Start-Process PowerShell.exe
}
#//====================================================================================//


# Main menu selections
#/======================================================================================/
do
{
    Show-Menu
    $Option = Read-Host -Prompt 'Please select an option'
    switch ($Option)
    {
        0 {Restart-PC}
        1 {Start-RelMon}
        2 {Reset-Update}
        3 {Reset-NetSet}
        4 {Start-ChkdskF}
        5 {Get-ChkdskRes}
        6 {Clear-CSC}
        7 {Clear-CredMan}
        8 {Clear-Edge}
        9 {Clear-Teams}
        10 {Reset-UwpApps}
        11{Remove-Chrome}
        12 {Start-BDEbak}
        13 {Start-BDE}
        14 {Remove-Profile}
        15 {Start-DismC}
        16 {Start-DismS}
        17 {Start-DismR}
        18 {Start-SFC}
        19 {Start-MemDiag}
        20 {Get-MemRes}
        21 {Get-PwrRep}
        22 {Get-BatRep}
        23 {Get-DevLog}
        24 {Start-Dfr}
        P {Start-PS}
        X {Exit}
    }
} until ($Option -eq 'X')
#//====================================================================================//
