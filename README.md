# IntuneNAMEOFSCRIPT.ps1
* these are run either via a script published via Intune or scheduled tasks, etc
* EventsMain: lots of visibility improvements for our endpoints
* Acrobat: uses a .NET async download for large files
* HWSW: lots of different data collection for endpoints



# Win10ITS Modules (NOT ALL FILES PORTED TO YOU)
* This module is installed on all Penn Law endpoints
* Updated via Proactive Remediation Script (Win10ITS); update removes old versions
* PWSH incompatibilities: AudioDeviceCmdlet, Bluetooth, Mute


# Command Reference
|Win10ITS|description|
| ------------   | ----------- |
|Backup-ThisPC|backup registry, downloads, appdata|
|Convert-LastTaskResult|translate Schedule Task Exit Codes (in decimal) to the task results |
|Convert-SIDGUID|SID to GUID|
|Convert-SubnetMask||
|ConvertTo-FlatObject|You can use this to flatten XML, JSON, and other arbitrary objects.|
|Convert-UTCtoLocal|[System.TimeZoneInfo]|
|Debug-Chrome|reopen chrome in debug mode|
|Disable-TeamsOpenAtLogin|change registry|
|Export-ITSExcel|ImportExcel to file, open downloads folder (not local admin)|
|Find-InPath|finds files in path|
|Find-InTemp|finds files in temp folders|
|Format-IntuneDeviceDiagnostics|microsoft script which reformats intune diagnostics|
|Format-XML|System.IO.StringWriter, System.XMl.XmlTextWriter|
|Get-ActiveConf|network traffice from zoom or teams|
|Get-AllDrivers|CIM Win32_PnPEntity, Win32_PnPSignedDriver|
|Get-ASREvents|Local events (more than what MDE returns)|
|Get-ClipITS|format clip to a single column (pscustomobject)|
|Get-ClipITSObject|format clip to rows/columns (pscustomobject)|
|Get-FileBitness|Eric Siron, PE signature|
|Get-FirewallInfo|Firewall-Manager (diff from default rules)|
|Get-FolderSizes|online vs ondisk|
|Get-HKEY|registry|
|Get-IMELogs|"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs" |
|Get-IntuneODC|Intune One Data Collector; PS5 only|
|Get-IntuneTranscripts|intune script transcripts|
|Get-Inven|full and basic inventory info|
|Get-ITSAdmin||
|Get-MDMEvents|MDM Events|
|Get-MSIEvents|MSI events |
|Get-MyI||
|Get-PerfCheck|Create a performance check|
|Get-ProfileList|Local / AAD SIDs|
|Get-PWSHEvents|Windows Powershell events (excl. ATP/Office/Intune)|
|Get-RestartRequired|RebootFlags|
|Get-SW|Registry 64/32 bit software info|
|Get-WDACEvents|@mattifestation)|
|Get-WDAGEvents||
|Get-WindowsInstallerMSI|C:\Windows\Installer\*.msi publishers|
|Install-ITSAcrobat|DownloadFileTaskAsync, event subscriptions, jobs|
|Install-JavaJRE|Evergreen update method + security/registry|
|Install-NewClassroom||
|Install-NewPC|calls intunenewcomputer.ps1|
|Install-O365Device|device based license|
|Install-Slack|slack via evergreen|
|Install-TeamViewer|installs Teamviewer (ITS or unattended/classroom)|
|New-Ticket|fresh service ticket (needs updating to ITSAzure version|
|Open-FirewallLog|uses cmtrace|
|Open-SyncML|olivier keiselbach|
|Publish-AzITSTableRow|AzStorage|
|Receive-ITSDownload|System.Net.WebClient, temp, outputs path |
|Receive-PennLawITS|updates local scripts/files|
|Remove-DellCU|Dell Command Update|
|Remove-HKEY|registry|
|Remove-ITSAdmin|LocalAdmin|
|Remove-OldProfiles|guest profiles|
|Repair-WindowsUpdate|winaero.com|
|Repair-WindowsUpdateTroubleShootingPack|uses classic troubleshooter (automated)|
|Reset-ThisPC|uses Dell SupportAssistOS recovery|
|Restart-AsAdmin|broken|
|Restart-PS||
|Restore-ThisPC|backup/restore|
|Send-Diags|uses microsoft support tooling, sends to azstorage|
|Send-EventsMain|sends events|
|Send-ITSLogs|Lots of event logs, panther, setupdiag.exe, Setupreport.cmd (bugs in wsh, perms)|
|Set-HKEY|registry|
|Set-Mute|System.Runtime.InteropServices, [audio]::mute|
|Set-PPTMonitor|setting default PPT monitor, requires run as user (system doesn't work)|
|Set-QuickAccess|un/pinning items to toolbar|
|Show-Notification|broken|
|Sync-Intune|sync device with intune|
|Sync-OneDriveToHDD|Archive, ReparsePoint'; attrib pinned/unpinned|
|Test-Admin|check if admin|
|Trace-ITS|netmon|
|Update-DellCU|runs Dell Command Update|
|Update-ITSSoftware|update standard software|
|Update-ManualWU|run windows update|
|Update-Win10ITS|update module|
|Write-ITSHost|[9:53:56] (green), host stream|
|Write-ToastNotification||
|Write-UpdateScreen|[9:53:56] (white), output stream|

