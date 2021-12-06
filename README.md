# PS_toolkit
PowerShell script to automate/facilitate some basic desktop support functions.
Most of it is pretty self-explanatory; it's essentially just a launcher for built-in Windows tools.

General Functions                                                 System Info
=======================================================           ================================
1. View chronological Stability Index                             Hostname:        $HostName
2. Reset Windows Update                                           OS Version:      $OSver
3. Reset network settings                                         OS Build:        $OSbuild
4. Detect and repair file system errors                           Model:           $PCModel
5. Get results of most recent file system check                   Boot Time:       $Boot
6. Clear Offline Files CSC for all users                          IPv4 Address:    $IPv4
7. Clear Edge cache for signed-in user                            Address Origin:  $IPOrigin
8. Clear Teams cache for signed-in user                           Default Gateway: $IPGate
9. Back up BitLocker recovery key to AD                           Drive Model:     $DiskMan$DiskMod  
                                                                  Drive Status:    $DiskStat
Windows OS Maintenance                                            PSU Status:      $Power
=======================================================
10. Check the component store log for errors
11. Scan the component store to detect errors
12. Rebuild the component store from Windows Update
13. Check Windows OS files and repair errors

Hardware Maintenance
=======================================================
14. Run memory diagnostic
15. Get results of most recent memory diagnostic
16. Get system power report
17. Get battery report (laptop only)
18. Get device installation log
19. Open Drive Optimizer

 0. Reboot     P. New PS prompt     ?. Help     X. Exit
