# Windows Troubleshooting Toolkit

<#
.DESCRIPTION
    Just a few tools I thought would be useful to have quick, easy access to
.NOTES
    Please be on the lookout for bugs, errors, or other unexpected behavior!
#>


# Prompt for Administrator rights
#/======================================================================================/
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -FilePath `"$PSCommandPath`"" -Verb RunAs
    Exit
}
#//====================================================================================//


# Get system info
#/======================================================================================/
Write-Host "Loading system information. Please wait . . ."

$script:User = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$script:UserDir = $User.Split('\')[1]
$script:OSbuild = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
$script:HostName = hostname
$script:PCModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$script:Boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$script:IPOrigin = (Get-NetIPAddress -AddressFamily IPv4).PrefixOrigin | Select-Object -First 1
$script:IPv4 = (Get-NetIPAddress -AddressFamily IPv4).IPAddress | Select-Object -First 1
$script:IPGate = ((Get-NetIPConfiguration).IPv4DefaultGateway).NextHop
$script:DiskMan = (Get-Disk -Number 0).Manufacturer
$script:DiskMod = (Get-Disk -Number 0).Model
$script:DiskStat = (Get-Disk -Number 0).HealthStatus
$Power = (Get-CimInstance -ClassName Win32_ComputerSystem).PowerSupplyState

# ----- Change "Dhcp" to "DHCP" (purely aesthetic) -----
if ($IPOrigin -eq 'Dhcp')
    {$script:IPOrigin = 'DHCP'}

# ----- The CIM query for PowerSupplyState returns a number; the associated PSU states are defined here: -----
# ----- https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem -----
if ($Power -eq 1)
    {$script:Power = 'Other'}
elseif ($Power -eq 2)
    {$script:Power = 'Unknown'}
elseif ($Power -eq 3)
    {$script:Power = 'Safe'}
elseif ($Power -eq 4)
    {$script:Power = 'Warning'}
elseif ($Power -eq 5)
    {$script:Power = 'Critical'}
elseif ($Power -eq 6)
    {$script:Power = 'Non-recoverable'}
else
    {$script:Power = 'No data'}

# ----- Match OS build number to Version -----
if ($OSbuild -like '*18363*')
    {$script:OSver = '1909'}
elseif ($OSbuild -like '*19041*')
    {$script:OSver = '2004'}
elseif ($OSbuild -like '*19042*')
    {$script:OSver = '20H2'}
elseif ($OSbuild -like '*19043*')
    {$script:OSver = '21H1'}
else
    {$script:OSver = 'Other' }  
#//====================================================================================//


# Main menu display
#/======================================================================================/
function Show-Menu
{
    Clear-Host
    Write-Host "General Functions                                                  System Info"
    Write-Host "=======================================================            ================================"
    Write-Host " 1. View chronological Stability Index                             Hostname:        $HostName"
    Write-Host " 2. Reset Windows Update                                           OS Version:      $OSver"
    Write-Host " 3. Reset network settings                                         OS Build:        $OSbuild"
    Write-Host " 4. Detect and repair file system errors                           Model:           $PCModel"
    Write-Host " 5. Get results of most recent file system check                   Boot Time:       $Boot"
    Write-Host " 6. Clear Offline Files CSC for all users                          IPv4 Address:    $IPv4"
    Write-Host " 7. Clear Edge cache for signed-in user                            Address Origin:  $IPOrigin"
    Write-Host " 8. Clear Teams cache for signed-in user                           Default Gateway: $IPGate" 
    Write-Host " 9. Back up BitLocker recovery key to AD                           Drive Model:     $DiskMan$DiskMod"   
    Write-Host "                                                                   Drive Status:    $DiskStat"
    Write-Host "Windows OS Maintenance                                             PSU Status:      $Power"
    Write-Host "======================================================="
    Write-Host "10. Check the component store log for errors"
    Write-Host "11. Scan the component store to detect errors"
    Write-Host "12. Rebuild the component store from Windows Update"
    Write-Host "13. Check Windows OS files and repair errors"
    Write-Host ""
    Write-Host "Hardware Maintenance"
    Write-Host "======================================================="
    Write-Host "14. Run memory diagnostic"
    Write-Host "15. Get results of most recent memory diagnostic"
    Write-Host "16. Get system power report"
    Write-Host "17. Get battery report (laptop only)"
    Write-Host "18. Get device installation log"
    Write-Host "19. Open Drive Optimizer"
    Write-Host ""
    Write-Host " 0. Reboot     P. New PS prompt     ?. Help     X. Exit"
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

    Remove-Item -Path "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.*"
    Remove-Item -Path "$env:SYSTEMROOT\SoftwareDistribution.bak" -Recurse
    Remove-Item -Path "$env:SYSTEMROOT\System32\catroot2.bak" -Recurse

    Rename-Item -Path "$env:SYSTEMROOT\SoftwareDistribution" -NewName "SoftwareDistribution.bak"
    Rename-Item -Path "$env:SYSTEMROOT\System32\catroot2" -NewName "catroot2.bak"

    sc.exe sdset bits --% D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
    sc.exe sdset wuauserv --% D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) 
   
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

    netsh.exe winsock reset
    netsh.exe winhttp reset proxy

    Start-Service -Name BITS
    Start-Service -Name CryptSvc
    Start-Service -Name wuauserv
    Start-Process sc.exe -ArgumentList "config bits start= delayed-auto"
    Start-Process sc.exe -ArgumentList "config cryptsvc start= auto"
    Start-Process sc.exe -ArgumentList "config wuauserv start= demand"

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

    # ----- Function to show final reboot prompt -----
    function Show-NetEnd
    {
        Clear-Host

        Write-Host "You must restart the computer to complete this operation."
        Write-Host ""

        $NetEnd = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
        switch ($NetEnd)
        {
            Y {Restart-PC}
            N {Show-Menu}        
        }
    }
    
    # ----- Function to delete NIC configuration data -----
    function Remove-NetCfg
    {
        netcfg.exe -d
        Show-NetEnd
    }
    
    # ----- Main NetSet routine -----
    $AdvProps = (Get-NetAdapterAdvancedProperty).DisplayName
    $Adapter = (Get-NetAdapter).Name
            
    Remove-NetIPAddress -Confirm:$false 2> $null

    Clear-DnsClientCache

    netsh.exe winsock reset
    netsh.exe int ip reset
    netsh.exe int tcp reset

    Reset-NetAdapterAdvancedProperty -DisplayName $AdvProps

    Restart-NetAdapter -Name $Adapter
        
    $NICdel = Read-Host -Prompt 'Would you also like to delete configuration data for all network devices? (Y/N)'
    switch ($NICdel)
    {
        Y {Remove-NetCfg}
        N {Show-NetEnd}        
    }
}
#//====================================================================================//


# [4] Detect and repair file system errors
#/======================================================================================/
function Start-ChkdskF
{
    Clear-Host

    chkdsk.exe /f
    
    # ----- See if we need to reboot -----
    $Dirty = chkntfs.exe c:

    if ($Dirty -like '*not*')
        {Show-Menu}
    else
    {
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

    $ChkdskEvt = Get-EventLog -LogName Application -Source Wininit |
        Where-Object {$_.Message -like '*checking file system*'} |
        Sort-Object TimeGenerated -Descending |
        Select-Object -First 1 -ExpandProperty Message
    $ChkdskMsg = $ChkdskEvt -split "`n" | 
        Select-String -Pattern 'Windows' | 
        Select-Object -Last 1
    $ChkdskEvent = Get-EventLog -LogName Application -Source Wininit |
        Where-Object {$_.Message -like '*checking file system*'} |
        Sort-Object TimeGenerated -Descending |
        Select-Object -First 1 -Property EventID,TimeGenerated
    $ChkdskID = $ChkdskEvent.EventID
    $ChkdskTime = $ChkdskEvent.TimeGenerated
    
    if ($ChkdskEvent)
    {        
        Write-Host "Channel:        Application"
        Write-Host "Source:         Microsoft-Windows-Wininit"
        Write-Host "EventID:        $ChkdskID"
        Write-Host "TimeCreated:    $ChkdskTime"
        Write-Host "Message:        $ChkdskMsg"
        Show-End
    }
    else
    {
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


# [6] Clear Offline Files CSC for all users
#/======================================================================================/
function Clear-CSC
{
    Clear-Host

    $CSCKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CSC\Parameters"

    if (Test-Path $CSCKey)
        {New-ItemProperty -Path $CSCKey -Name FormatDatabase -PropertyType Dword -Value 1 -Force}
    else {
        New-Item -Path $CSCKey
        New-ItemProperty -Path $CSCKey -Name FormatDatabase -PropertyType Dword -Value 1 -Force
    }

    Write-Host "You must restart the computer to complete this operation."

    $CSCend = Read-Host -Prompt 'Would you like to restart now? (Y/N)'
    switch ($CSCend)
    {
        Y {Restart-PC}
        N {Show-Menu}        
    }
}
#//====================================================================================//


# [7] Clear Edge cache for signed-in user
#/======================================================================================/
function Clear-Edge
{
    Clear-Host
    Write-Host "Ensuring Edge is stopped . . ."
    Write-Host ""
    
    Stop-Process -Name msedge -Force 2> $null
    
    Write-Host "Clearing cached data for $User . . ."

    # ----- Ensure Edge has enough time to stop -----
    Start-Sleep -Seconds 3

    Push-Location "C:\Users\$UserDir\AppData\Local\Microsoft\Edge\User Data\Default"
    Remove-Item "cookies","Login Data","Web Data","Cache","IndexedDB" -Force -Recurse 2> $null
    Pop-Location

    Show-End
}
#//====================================================================================//


# [8] Clear Teams cache for signed-in user
#/======================================================================================/
function Clear-Teams
{
    Clear-Host
    Write-Host "Ensuring Teams is stopped . . ."
    Write-Host ""

    Stop-Process -Name Teams -Force 2> $null
    
    Write-Host "Clearing cached data for $User . . ."

    # ----- Ensure Teams has enough time to stop -----
    Start-Sleep -Seconds 3

    Push-Location "C:\Users\$UserDir\AppData\Roaming\Microsoft\Teams"
    Remove-Item "Cache","blob_storage","databases","GPUCache","IndexedDB","Local Storage","tmp" -Force -Recurse 2> $null
    Pop-Location

    Show-End
}
#//====================================================================================//


# [9] Back up BitLocker recovery key to Active Directory
#/======================================================================================/
function Start-BDEbak
{
    Clear-Host
    Write-Host "Backing up BitLocker Recovery Key to Active Directory."
    Write-Host

    $KeyID = ((Get-BitLockerVolume -MountPoint C:).KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorID
        
    Backup-BitLockerKeyProtector -MountPoint C: -KeyProtectorId $KeyID

    Show-End
}
#//====================================================================================//


#    //===========================================================================//
#    //                                                                           //
#    //                          WINDOWS OS MAINTENANCE                           //
#    //                                                                           //
#    //===========================================================================//


# [10] Check the component store log for errors
#/======================================================================================/
function Start-DismC
{
    Clear-Host

    Repair-WindowsImage -Online -CheckHealth
    
    Show-End
}
#//====================================================================================//


# [11] Scan the component store to detect errors
#/======================================================================================/
function Start-DismS
{
    Clear-Host

    Repair-WindowsImage -Online -ScanHealth

    Show-End
}
#//====================================================================================//


# [12] Rebuild the component store from Windows Update
#/======================================================================================/
function Start-DismR
{
    Clear-Host

    Repair-WindowsImage -Online -RestoreHealth

    Show-End
}
#//====================================================================================//


# [13] Check Windows OS files and repair errors
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


# [14] Run memory diagnostic
#/======================================================================================/
function Start-MemDiag
{
    Start-Process MdSched.exe
}
#//====================================================================================//


# [15] Get results of most recent memory diagnostic
#/======================================================================================/
function Get-MemRes
{
    Clear-Host

    $MemEvent = Get-EventLog -LogName System -Source Microsoft-Windows-MemoryDiagnostics-Results |
        Sort-Object -Property TimeGenerated -Descending |
        Select-Object -First 1 -Property EventID,TimeGenerated,Message
    $MemID = $MemEvent.EventID
    $MemTime = $MemEvent.TimeGenerated
    $MemMsg = $MemEvent.Message

    if ($MemEvent) {      
        Write-Host "Channel:     System"  
        Write-Host "Source:      Microsoft-Windows-MemoryDiagnostics-Results"
        Write-Host "EventID:     $MemID"
        Write-Host "TimeCreated: $MemTime"
        Write-Host "Message:     $MemMsg"
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


# [16] Get system power report
#/======================================================================================/
function Get-PwrRep
{
    Clear-Host
    Write-Host "Generating system power report. Please wait . . ."
    
    Start-Process powercfg.exe -ArgumentList "/systempowerreport /duration 7"
        
    Invoke-Item C:\Windows\System32\sleepstudy-report.html
}
#//====================================================================================//


# [17] Get battery report
#/======================================================================================/
function Get-BatRep
{
    Clear-Host
    Write-Host "Generating battery report. Please wait . . ."

    Start-Process powercfg.exe -ArgumentList "/batteryreport /duration 7"
    Start-Sleep -Seconds 5

    Invoke-Item C:\Windows\System32\battery-report.html
}
#//====================================================================================//


# [18] Get device installation log
#/======================================================================================/
function Get-DevLog
{
    Invoke-Item C:\Windows\INF\setupapi.dev.log
}
#//====================================================================================//


# [19] Open Drive Optimizer
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
do {
    Show-Menu
    $selection = Read-Host -Prompt 'Please select an option'
    switch ($selection)
    {
        0 {Restart-PC}
        1 {Start-RelMon}
        2 {Start-ProcExp}
        3 {Reset-Update}
        4 {Reset-NetSet}
        5 {Start-ChkdskF}
        6 {Get-ChkdskRes}
        7 {Clear-CSC}
        8 {Clear-CredMan}
        9 {Clear-Edge}
        10 {Clear-Teams}
        11 {Start-BDEbak}
        12 {Start-DismC}
        13 {Start-DismS}
        14 {Start-DismR}
        15 {Start-SFC}
        16 {Start-MemDiag}
        17 {Get-MemRes}
        18 {Get-PwrRep}
        19 {Get-BatRep}
        20 {Get-DevLog}
        21 {Start-Dfr}
        P {Start-PS}
        X {Exit}
    }
} until ($selection -eq 'x')
#//====================================================================================//
