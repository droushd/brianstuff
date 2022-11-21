Param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$override,
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$clean
  )

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:ErrorActionPreference = "SilentlyContinue"

Function global:Write-UpdateScreen ($message) {Write-Output "[$(Get-Date -format "H:mm:ss")] $message"}

function Convert-FileSize {
    param($bytes)
    if ($bytes -lt 1MB) {return "$([Math]::Round($bytes / 1KB, 2)) KB"}
    elseif ($bytes -lt 1GB) {return "$([Math]::Round($bytes / 1MB, 2)) MB"}
    elseif ($bytes -lt 1TB) {return "$([Math]::Round($bytes / 1GB, 2)) GB"}
}

try {
    $private:runtime =  [system.diagnostics.stopwatch]::StartNew()
    $private:perfchecks = New-Object System.Collections.ArrayList($null)  #New-Object PSCustomObject
    # $private:maintenancewindow = (get-date).Hour -lt 6 -or (get-date).Hour -gt 22 -or (Get-Date).DayOfWeek.value__ -match "6|0"
	$private:ScriptName = "IntuneAcrobatInstall.ps1" 
    $private:itsallTable = "InstallAdobe"
	$private:transcript = $("$env:temp\$ScriptName" + $(Get-Date -Format 'MM-dd-yyyy-hh-mm-ss') + ".txt") -replace ".ps1","_" 
    Start-Transcript -Path $transcript  -IncludeInvocationHeader | ForEach-Object {Write-UpdateScreen $_}
    $ErrorActionPreference = "SilentlyContinue"
    $jobdonepath = "C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.txt"

    if ($PSCommandPath -match 'droush') {
        Write-UpdateScreen "Publishing updated version of script first"
        Publish-AzITSAll .\$ScriptName
        Remove-Item $jobdonepath -Force -ErrorAction SilentlyContinue
    }

	$Win10ITSexists_min = '1.4.52.0'
	$Win10ITSexists_current = Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\Win10ITS" | Sort-Object name -Descending | Where-Object {[version]$_.name -gt $Win10ITSexists_min}
  	$GII = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue
	if ($GII -And $Win10ITSexists_current) {
        Write-UpdateScreen "using Get-Inven"
        # $ordered = "A_"  
		$private:hw = Get-Inven -basic -ordered $ordered
    }
	else {
		$ordered = ""
		$private:hw = New-Object 'system.collections.generic.dictionary[string,string]'
        $hw["$($ordered)ExitCode"] = 1641
        $hw["$($ordered)ExitReason"] = "Win10ITS DNE/Old"
		Write-UpdateScreen "FAILURE: Win10ITS Not Installed or Not Current" 
		$itsallfile_sas = "sv=2020-02-10&ss=f&srt=sco&sp=rl&se=2031-03-08T02:13:06Z&st=2021-03-07T18:13:06Z&spr=https&sig=AyUrZCTtW6nFDiKGPgIIxV7isUZA5g8Hgcb8CawBEbk%3D"
		$URI = "https://itsall.file.core.windows.net/installers/IntunePSUpdates.ps1?$itsallfile_sas"
		$outpath = "$env:temp\IntunePSUpdates.ps1"
		$wc = New-Object System.Net.WebClient 
		try {$wc.DownloadFile($URI, $outpath) | Out-Null} catch {Write-Output "[$(Get-Date -format "H:mm:ss")] Failed to download: $outpath"}
		try{&"$env:temp\IntunePSUpdates.ps1"} catch {Write-UpdateScreen "Failed PSUpdates this time";$($hw["$($ordered)ExitCode"])}
		invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"$PSCommandPath`" -noprofile";
		Exit $($hw["$($ordered)ExitCode"])
	}

    $hw['PartitionKey'] = "$([System.Net.Dns]::GetHostName())"
	$hw['RowKey'] =   $ScriptName


	$isclassroom = $env:computername -match "Class|Tablet" -or $($hw['IntuneUPN']) -match "classroom"
	$isshared =  $(	$hw['IntuneUPN']) -match "itsclient|deviceenroll"
	if ($isclassroom) {Write-UpdateScreen "Classroom: $($hw['IntuneUPN'])"; Exit 0}
	if ($isshared) {Write-UpdateScreen "Shared: $($hw['IntuneUPN'])"}


    if ($clean) {
        get-process | Where-Object {$_.company -match 'Adobe'} | ForEach-Object {Stop-Process -Id $PSItem.Id -Force -Verbose} 
        $cleaner = "AdobeCreativeCloudCleanerTool.exe"
        $url = "https://itsall.file.core.windows.net/installers/$($cleaner)?sv=2018-03-28&ss=f&srt=sco&sp=r&se=2029-06-21T20:12:54Z&st=2019-06-22T12:12:54Z&spr=https&sig=Ct0CGPnh1QntF4HTxSMeyjbrDYHFeZehhvwY6CeFffg%3D"
        $wc = New-Object System.Net.WebClient 
        $wc.DownloadFile($url, "$env:temp\$cleaner") | Out-Null  
        $cleanerxml = "cleanup.xml"
        $url = "https://itsall.file.core.windows.net/installers/$($cleanerxml)?sv=2018-03-28&ss=f&srt=sco&sp=r&se=2029-06-21T20:12:54Z&st=2019-06-22T12:12:54Z&spr=https&sig=Ct0CGPnh1QntF4HTxSMeyjbrDYHFeZehhvwY6CeFffg%3D"
        $wc = New-Object System.Net.WebClient 
        $wc.DownloadFile($url, "$env:temp\$cleanerxml") | Out-Null  
        $log = "$env:temp\Adobe Creative Cloud Cleaner Tool.log"
        if (test-path $Log) {Remove-Item $log -Force}
        Start-Process -filepath "$env:temp\$cleaner" -argumentlist "--removeAll=ALL"  -NoNewWindow -Wait
        Get-Content $log
        Get-WindowsInstallerMSI | Where-Object {$_.subject -match "Adobe"} | ForEach-Object {
            Write-UpdateScreen "Uninstalling: $($_.fullname)"
            Start-Process -FilePath msiexec -ArgumentList "/X $($_.fullname) /qn REBOOT=REALLYSUPRESS" -Wait
        }
            
        if ((Get-RestartRequired)) {
            schtasks.exe /create /f /tn "PennLawIntuneAcrobatInstall" /ru SYSTEM /tr "powershell -ex bypass -file 'C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1' -noprofile" /sc DAILY /st 02:00 /du 0159 /ri 15 | ForEach-Object {Write-Output "[$(Get-Date -uformat %R)] $PSItem"}
            schtasks.exe /create /f /tn "PennLawIntuneAcrobatInstallStartup" /ru SYSTEM /sc ONSTART /tr "powershell -executionpolicy bypass -command &{Start-ScheduledTask PennLawIntuneAcrobatInstall}" | ForEach-Object {Write-Output "[$(Get-Date -uformat %R)] $PSItem"}
            shutdown -r -t 10 /c "Penn Law ITS: Restarting Before Installing Adobe Acrobat" /d P:2:4
        }
    }

    $isInstalled = get-sw | Where-Object {$_.displayname -match "Adobe Acrobat DC|Adobe Creative Cloud"} | ForEach-Object {"$($_.displayname)$($_.displayversion);$($_.installdate);$($_.installsource -match 'LawAcrobat')"}
    $hw['installedSW'] = $isInstalled  #$sw | where {$_.displayname -match $displayname } | % {"$($_.DisplayName):$($_.displayversion):$($_.installdate)"} 
    if ($isInstalled) {
        $shortcutfilename = 'InstallAcrobat.lnk'
        $special = [system.environment]::GetFolderPath("CommonDesktopDirectory")
        if (Test-Path "$special\$shortcutfilename") {Remove-Item "$special\$shortcutfilename" -Force}
        # Copy-Item $transcript $jobdonepath -Force
        # $jobdone = Test-Path $jobdonepath            
        Get-ScheduledTask | Where-Object {$_.TaskName -match "PennLawIntuneAcrobatInstall"} | ForEach-Object {
            Unregister-ScheduledTask -TaskName $PSItem.taskname -Confirm:$false -ErrorAction SilentlyContinue
             Write-UpdateScreen "Scheduled Task Successfully Removed: $($PSItem.taskname)" 
        }
        $hw['ExitCode'] = 0
        $hw['ExitReason'] = "Success Acrobat Installed"
        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        Exit 0
    }
    elseif ($null -eq $isInstalled) {
        powercfg.exe -x -standby-timeout-ac 0
    }

    $taskname = "PennLawIntuneAcrobatInstall"
    $tasknameexists = Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue
    $isInstalled = Get-SW | Where-Object {$_.displayname -match "Adobe Acrobat DC|Adobe Creative Cloud"} | ForEach-Object {"$($_.displayname)$($_.displayversion);$($_.installdate);$($_.installsource -match 'LawAcrobat')"}
    $taskcompleted = Test-Path 'C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.txt'
    if (-not$tasknameexists -and -not$taskcompleted) {
      schtasks.exe /create /f /tn $taskname /ru SYSTEM /tr "powershell -ex bypass -file 'C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1' -noprofile" /sc DAILY /st 02:00 /du 0159 /ri 180 | ForEach-Object {Write-UpdateScreen $PSItem}
      schtasks.exe /create /f /tn "PennLawIntuneAcrobatInstallStartup" /ru SYSTEM /sc ONSTART /tr "powershell -ex bypass -file 'C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1' -noprofile" | ForEach-Object {Write-UpdateScreen $PSItem}
    }


    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()
    # $acrobatsetup = Test-Path "$env:temp\LawAcrobat\Build\setup.exe"
    $setupExists = Test-Path "$env:temp\LawAcrobat\Build\setup.exe"
    $zipExists = Test-Path "$env:temp\LawAcrobat_en_US_WIN_64.zip" 
    
	$itsallfile_sas = "sv=2020-02-10&ss=f&srt=sco&sp=rl&se=2031-03-08T02:13:06Z&st=2021-03-07T18:13:06Z&spr=https&sig=AyUrZCTtW6nFDiKGPgIIxV7isUZA5g8Hgcb8CawBEbk%3D"
    $uri = "https://itsall.file.core.windows.net/installers?restype=directory&comp=list&$itsallfile_sas" 
    $Destination = "$env:temp\result.xml"
    $wc = New-Object System.Net.WebClient 
    try {$wc.DownloadFile($URI, $Destination) | Out-Null} catch {Write-Output "[$(Get-Date -format "H:mm:ss")] Failed to download: $destination"}
    [xml]$a = Get-Content $Destination
    $zipSizeAzure = $a.EnumerationResults.entries.file | Where-Object {$_.name -eq 'LawAcrobat_en_US_WIN_64.zip' } | ForEach-Object {$_.properties.'content-length'}
    if ($null -eq $zipSizeAzure) {
        $zipSizeAzure = 2831217446
    }

    $zipExists = Test-Path "$env:temp\LawAcrobat_en_US_WIN_64.zip"
    $zipSizeCorrect = Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | ForEach-Object {$_.length -eq $zipSizeAzure}
    Write-UpdateScreen "$env:temp\LawAcrobat_en_US_WIN_64.zip exists: $zipexists and is complete: $zipSizeCorrect"
    if ($zipExists -And -not$zipSizeCorrect) {
        # Get-ScheduledTask | where {$_.taskname -match 'Acrobat'} | Start-ScheduledTask
        Write-UpdateScreen "Removing bad download of $env:temp\LawAcrobat_en_US_WIN_64.zip"
        Start-job -scriptblock {Remove-Item "$env:temp\LawAcrobat_en_US_WIN_64.zip" -Force -ErrorAction SilentlyContinue} -name "DeleteBad"
        Wait-job -name "DeleteBad"
    }
    elseif ($zipExists -ANd $zipSizeCorrect) {
        Start-job -scriptblock {Expand-Archive -Path "$env:temp\LawAcrobat_en_US_WIN_64.zip" -DestinationPath $env:temp -Force} -name "Zippityzip"
        Wait-job -name "Zippityzip"            
        Write-UpdateScreen "Expanded Setup.exe"
        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
    }
    $setupExists = Test-Path "$env:temp\LawAcrobat\Build\setup.exe"
    # elseif ($PSCommandPath -match "C:\Windows\Temp") {exit 3}
    if (-not$setupexists) {
        $stopwatchSplit =  [system.diagnostics.stopwatch]::StartNew()

        try {
            # Write-UpdateScreen "Download the installer" 
            $outpath = "$env:temp\LawAcrobat_en_US_WIN_64.zip"
            $url = "https://itsall.file.core.windows.net/installers/LawAcrobat_en_US_WIN_64.zip?sv=2018-03-28&ss=f&srt=sco&sp=r&se=2029-06-21T20:12:54Z&st=2019-06-22T12:12:54Z&spr=https&sig=Ct0CGPnh1QntF4HTxSMeyjbrDYHFeZehhvwY6CeFffg%3D"
            $wc = New-Object System.Net.WebClient
            $outfile = $wc.DownloadFileTaskAsync($url, $outpath)
            Unregister-event WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue
            Register-ObjectEvent -InputObject $wc -EventName DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged | Out-Null            
            
            Start-Sleep -Seconds 3 # Wait two seconds for the registration to fully complete
            
            while (!($outfile.IsCompleted)) { # While the download is showing as not complete, we keep looping to get event data.
                $zipSizeCorrect = Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | ForEach-Object {$_.length -eq $zipSizeAzure} 
                $zipStuck = Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | ForEach-Object {(Get-Date $_.LastWriteTime) -lt (Get-Date).AddMinutes(-15)}
                if ($zipStuck) {
                    Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | 
                        ForEach-Object {Write-UpdateScreen "zip download last write time is $($_.LastWriteTime)"}
                    Get-ScheduledTask | Where-Object {$_.TaskName -match "Acrotbat"} | Start-ScheduledTask 
                    Remove-Item "$env:temp\LawAcrobat_en_US_WIN_64.zip" -Force -ErrorAction SilentlyContinue 
                    Write-UpdateScreen "Removing bad download of $env:temp\LawAcrobat_en_US_WIN_64.zip; Exit and start again"
                    Exit 3
                }
                Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | ForEach-Object {
                    try {
                        $total = "$zipSizeAzure"
                        $sofar = $_.length
                        $a = ($sofar/$total)*100 | ForEach-Object {[Math]::Round($PSItem,2)}
                        Write-Host -NoNewLine "`r[$(Get-Date -uformat %R)] Download the installer: $a% complete; Elapsed $([math]::Round($stopwatchSplit.elapsed.totalminutes,2))" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
                        Start-Sleep 20
                    }
                    catch{}
                }

                if ($outfile.IsFaulted) {
                    Write-UpdateScreen "An error occurred. Generating error."
                    Write-Error $outfile.GetAwaiter().GetResult()
                    break
                }                

                $EventData = Get-Event -SourceIdentifier WebClient.DownloadProgressChanged | Select-Object -ExpandProperty "SourceEventArgs" -Last 1
                $ReceivedData = ($EventData | Select-Object -ExpandProperty "BytesReceived")
                $TotalToReceive = ($EventData | Select-Object -ExpandProperty "TotalBytesToReceive")
                $TotalPercent = $EventData | Select-Object -ExpandProperty "ProgressPercentage"

                if(($host.Name -match 'consolehost')) {Write-Progress -Activity "Downloading File" -Status "Percent Complete: $($TotalPercent)%" -CurrentOperation "Downloaded $(convert-FileSize -bytes $ReceivedData) / $(convert-FileSize -bytes $TotalToReceive)" -PercentComplete $TotalPercent}
            }
            Unregister-event WebClient.DownloadProgressChanged
            }
        catch [Exception] {
            $ErrorDetails = $_
            Unregister-event WebClient.DownloadProgressChanged
            switch ($ErrorDetails.FullyQualifiedErrorId) {
                "ArgumentNullException" { 
                    Write-Error -Exception "ArgumentNullException" -ErrorId "ArgumentNullException" -Message "Either the Url or Path is null." -Category InvalidArgument -TargetObject $Downloader -ErrorAction Stop
                }
                "WebException" {
                    Write-Error -Exception "WebException" -ErrorId "WebException" -Message "An error occurred while downloading the resource." -Category OperationTimeout -TargetObject $Downloader -ErrorAction Stop
                }
                "InvalidOperationException" {
                    Write-Error -Exception "InvalidOperationException" -ErrorId "InvalidOperationException" -Message "The file at ""$($Path)"" is in use by another process." -Category WriteError -TargetObject $Path -ErrorAction Stop
                }
                Default {
                    Write-Error $ErrorDetails -ErrorAction Stop
                }
            }
            $hw['ExitCode'] = 1641
            $hw['ExitReason'] = "Download Failed"
            Receive-PennLawITS
            Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Download failed"
            invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1`" -noprofile";
            Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
            Exit 1641
        }
        $stopwatchSplit.Stop()
        $stopwatchSplit

        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null

        Write-UpdateScreen "Download complete" 
        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        $zipExists = Test-Path "$env:temp\LawAcrobat_en_US_WIN_64.zip"
    }

    $zipSizeCorrect = Get-ChildItem -ErrorAction SilentlyContinue "$env:temp\LawAcrobat_en_US_WIN_64.zip" | ForEach-Object {$_.length -eq $zipSizeAzure}
    Write-UpdateScreen "$env:temp\LawAcrobat_en_US_WIN_64.zip exists: $zipexists and is complete: $zipSizeCorrect"
    if ($setupexists) {}
    elseif (-not$zipSizeCorrect) {
        Start-job -scriptblock {Remove-Item "$env:temp\LawAcrobat_en_US_WIN_64.zip" -Force -ErrorAction SilentlyContinue} -name "DeleteRestart"
        Write-UpdateScreen "Perfcheck: DeleteRestart" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
        Wait-job -name "DeleteRestart"            
        $hw['ExitCode'] = 1641
        $hw['ExitReason'] = "Zip Exists but is not correct size"
        Receive-PennLawITS
        Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Zip Exists but is not correct size"
		invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1`" -noprofile";
		Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        Exit 1641
    }
    elseif ($zipExists -And $zipSizeCorrect) {
        Start-job -scriptblock {Expand-Archive -Path "$env:temp\LawAcrobat_en_US_WIN_64.zip" -DestinationPath $env:temp -Force} -name "Zippityzip"
        Write-UpdateScreen "Perfcheck: Zippityzip" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
        Wait-job -name "Zippityzip"            
        Write-UpdateScreen "Expanded Setup.exe"
        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        $setupExists = Test-Path "$env:temp\LawAcrobat\Build\setup.exe"
    }
    if ($setupExists) {
        $shortcutfilename = 'InstallAcrobat.lnk'
        $special = [system.environment]::GetFolderPath("CommonDesktopDirectory")
        if (Test-Path "$special\$shortcutfilename") {Remove-Item "$special\$shortcutfilename" -Force}
        $w = New-Object -ComObject WScript.Shell
        $link = $w.CreateShortcut("$special\$shortcutfilename")
        $link.arguments = "-command &{&`"$env:temp\LawAcrobat\Build\setup.exe`"}"
        $link.TargetPath = 'c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe' 
        $link.workingDirectory = "$env:temp\LawAcrobat\Build\"
        $link.save() > $null

        $bytes = [System.IO.File]::ReadAllBytes("$special\$shortcutfilename")
        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes("$special\$shortcutfilename", $bytes)
        $hw['shortcut'] = test-path "$special\$shortcutfilename"
        Write-UpdateScreen "Installing Acrobat"
        Start-Process -FilePath "$env:temp\LawAcrobat\Build\setup.exe" -ArgumentList "--silent" -nonewwindow -Wait
        # $process | ForEach-Object {Write-UpdateScreen "Updating: $($_.startinfo.filename)"}
        # $hw['inProgress'] = "PID: $($process.id)"    
        # Write-UpdateScreen "Perfcheck: Installing" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
        # Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        # if ($schedtask) {
        #     try {Wait-Process -InputObject $process -ErrorAction SilentlyContinue} catch{}    
        # }
        
        Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
    }
    else {
        $hw['ExitCode'] = 1641
        $hw['ExitReason'] = "Failed to find setup.exe"
        Receive-PennLawITS
        Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Failed to find setup.exe"
		invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1`" -noprofile";
		Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
        Exit 1641
    }
    
    $hw['Runtime'] = [Math]::Round($runtime.elapsed.TotalMinutes,2)
    Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
    # Write-Output "Time Elapsed for DL+Install (sec): $([math]::Round($stopwatch.Elapsed.TotalSeconds,0))"
    $stopwatch.Stop()
      
    $sw = Get-SW
    $isInstalled = $sw | Where-Object {$_.displayname -match "Adobe Acrobat DC|Adobe Creative Cloud"} | ForEach-Object {"$($_.displayname)$($_.displayversion);$($_.installdate);$($_.installsource -match 'LawAcrobat')"}
    if ($isInstalled) {
        Write-UpdateScreen "Acrobat is installed: $isinstalled"
        $shortcutfilename = 'InstallAcrobat.lnk'
        $special = [system.environment]::GetFolderPath("CommonDesktopDirectory")
        if (Test-Path "$special\$shortcutfilename") {Remove-Item "$special\$shortcutfilename" -Force}
        # Copy-Item $transcript $jobdonepath -Force
        # $jobdone = Test-Path $jobdonepath            
        Get-ScheduledTask | Where-Object {$_.TaskName -match "PennLawIntuneAcrobatInstall"} | ForEach-Object {
            Unregister-ScheduledTask -TaskName $PSItem.taskname -Confirm:$false -ErrorAction SilentlyContinue
             Write-UpdateScreen "Scheduled Task Successfully Removed: $($PSItem.taskname)" 
        }
        Get-ScheduledTask | Where-Object {$_.TaskName -match "NewComputer"} | Start-ScheduledTask
    
        $hw['ExitCode'] = 0
        $hw['ExitReason'] = "Success Acrobat Installed"
    }
    else {
        Receive-PennLawITS
        Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Failed after install step"
        if (-not$clean) {
            Start-Process -FilePath PowerShell -ArgumentList "-ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1`" -clean -noprofile"#-PassThru #| foreach {$_}
            $hw['ExitCode'] = 1641
            $hw['ExitReason'] = "Failed Install: retry as CLEAN" 
        }
        else {
            Invoke-Command {
                New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -erroraction silentlycontinue 
                $ProtocolHandler = get-item 'HKCR:\ToastReboot' -erroraction 'silentlycontinue'
                if (!$ProtocolHandler) {
                    #create handler for reboot
                    New-item 'HKCR:\ToastReboot' -force 
                    set-itemproperty 'HKCR:\ToastReboot' -name '(DEFAULT)' -value 'url:ToastReboot' -force
                    set-itemproperty 'HKCR:\ToastReboot' -name 'URL Protocol' -value '' -force
                    new-itemproperty -path 'HKCR:\ToastReboot' -propertytype dword -name 'EditFlags' -value 2162688
                    New-item 'HKCR:\ToastReboot\Shell\Open\command' -force
                    set-itemproperty 'HKCR:\ToastReboot\Shell\Open\command' -name '(DEFAULT)' -value 'C:\Windows\System32\shutdown.exe -r -t 10 /c "Penn Law ITS: Restarting to Continue Updates (TOAST)" /d P:2:4' -force
                }
            } | Out-Null
        
            
            try {
                invoke-ascurrentuser -scriptblock {
                $heroimage = New-BTImage -Source 'https://www.law.upenn.edu/live/resource/image/images/design/logo-footer.rev.1574106327.png' -HeroImage -Crop Circle
                $Text1 = New-BTText -Content  "Penn Law ITS Notification: $(Get-Date -format s)"
                $Text2 = New-BTText -Content "Please restart your computer to continue setup."
                $Button = New-BTButton -Content "Dismiss" -dismiss 
                $Button2 = New-BTButton -Content "Reboot now" -Arguments "ToastReboot:" -ActivationType Protocol
                $5Min = New-BTSelectionBoxItem -Id 5 -Content '5 minutes'
                $10Min = New-BTSelectionBoxItem -Id 10 -Content '10 minutes'
                $1Hour = New-BTSelectionBoxItem -Id 60 -Content '1 hour'
                $4Hour = New-BTSelectionBoxItem -Id 240 -Content '4 hours'
                $1Day = New-BTSelectionBoxItem -Id 1440 -Content '1 day'
                $Items = $5Min, $10Min, $1Hour, $4Hour, $1Day
                $SelectionBox = New-BTInput -Id 'SnoozeTime' -DefaultSelectionBoxItemId 10 -Items $Items
                $action = New-BTAction -Buttons $Button, $Button2 -inputs $SelectionBox
                $Binding = New-BTBinding -Children $text1, $text2 -HeroImage $heroimage
                $Visual = New-BTVisual -BindingGeneric $Binding
                $Content = New-BTContent -Visual $Visual -Actions $action
                Submit-BTNotification -Content $Content
                Write-Output "[$(Get-Date -format "H:mm:ss")] SUCCESS: Restart sent message to user"
                }
            }
            catch{Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Restart but cannot message user (FAILED PROB SYSTEM)"}
            $hw['ExitCode'] = 1641
            $hw['ExitReason'] = "Failed Install: retry RESTART" 
        }

    }
    # Get-ScheduledTask | Where-Object {$_.TaskName -match "NewComputer"} | Start-ScheduledTask 
    $hw['installedSW'] = $isInstalled  #$sw | where {$_.displayname -match $displayname } | % {"$($_.DisplayName):$($_.displayversion):$($_.installdate)"} 
    # $hw['msiEvents'] = Get-MSIEvents | Select-Object -first 100 | ForEach-Object {"$(Get-Date $_.TimeCreated -format s): $($_.Message)"} | Convertto-Json
    $hw['z_CPUpct'] = get-process -Id $pid | ForEach-Object {
        $TotalSec = (New-TimeSpan -Start $_.StartTime).TotalSeconds
        [Math]::Round( ($_.CPU * 100 / $TotalSec), 0)
    }
    $hw['z_PeakWS'] = get-process -Id $pid | ForEach-Object {[math]::Round($_.peakworkingset64/1MB,0)}	
    $hw['z_Runtime'] = [Math]::Round($runtime.elapsed.TotalMinutes,2)
    $avgCPU = $perfchecks.cpupct | Measure-Object -average | ForEach-Object {$_.average}
    $avgRAM = $perfchecks.rampct | Measure-Object -average | ForEach-Object {$_.average}
    $hw['z_perfall'] = $perfchecks | out-string
    $hw['z_perfCPU'] = [math]::Round($avgCPU,0) 
    $hw['z_perfRAM'] = [math]::Round($avgRAM,0) 
   
    Publish-AzITSTableRow -logentry $hw -table $itsallTable | Out-Null
    Exit $($hw['ExitCode']) 
}

catch
{
    $_
    $hw['ExitCode'] = 8469
    $hw['ExitReason'] = "Failed in the catch statement"
    Receive-PennLawITS
    Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Failed after install step"
    # invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAcrobatInstall.ps1`" -noprofile";
    Publish-AzITSTableRow -logentry $hw -table $itsallTable -catch $_ -iserror $true -isdiagnostics $transcript | Out-Null
    Exit $($hw['ExitCode']) 
}
finally {
	Write-UpdateScreen "Finally Block: Exiting" 
    $ErrorActionPreference = "Continue"
    try{
        stop-transcript|out-null
      }
      catch [System.InvalidOperationException]{}
}

# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVfrCNn38BDpCEHxJCXln+PYg
# Ut2gggNOMIIDSjCCAjKgAwIBAgIQQs0k/mo5TKhBtQoi6Y4h/TANBgkqhkiG9w0B
# AQsFADAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbTAe
# Fw0yMDA1MTIxNDAyMTlaFw0yMTA1MTIxNDEyMTlaMCgxJjAkBgNVBAMMHXBlbm5s
# YXdzY2hvb2wub25taWNyb3NvZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEA8Dy7eApwT7FITi/2nmejLd9542rs20G0BlhNis7+JA35o827w74K
# xIqRfHoqWh+UxJtD/GK0flaHlZOJFD2/a4OSiNg9DMDn4bC1fRu3iJt1/JNSvm8e
# ULCJ7J/MWLJJcg/aT/Eb4yrXAFGUJBHLc3A/yN7tUO/E84OlFWXBr+IAT17VpXRm
# ojZIXw+rvrbNgQXWvyNK+gBSx9IYT4+FUp8633HmdZxGKnfzPAO03pUc1iJzpp84
# EUV/jPO44gAoilw/3uhG0vqYETPfG1ZtMjswKetjTjh4HPV4ZkoV4EBFvV5wivCm
# X8dQEdZcPIeIOTuMqZqZDnnBE+ZnfCZ+bQIDAQABo3AwbjAOBgNVHQ8BAf8EBAMC
# B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwKAYDVR0RBCEwH4IdcGVubmxhd3NjaG9v
# bC5vbm1pY3Jvc29mdC5jb20wHQYDVR0OBBYEFBka50+hI6kXKI6hn4XGMq/Xznni
# MA0GCSqGSIb3DQEBCwUAA4IBAQDCG6vZPWtfz9U5dO8edDNx7Vu3SkDycU4/Sqow
# fac3a2sATGusSYJI7AqWbqPdO6+JWHNEVFJyrGOfj+rGMVTmigO5NwuV9cT7Wc7k
# aA8BZ0+6S+GqLBo+mW/8dijy98SDhXIIsp7Z8e+inANc+TwOYSdgb1LDNB8DrDcz
# +nETOd28b5gB1Ltx7awEukK6DGmeqbZggGPGqLD6omOVEVJtRkrYjFAV25cd+89w
# Sy3I+JyXPPa3+YRgF0CGmQtvv0bTdG+PXVw/an7at7FDVIqVdVsDVSm4+tzvmbSY
# kNU+cyKiwYbOVTVJstzRqmSHuFfIks6KjkK0hmQS8FOwJDUJMYIB3TCCAdkCAQEw
# PDAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbQIQQs0k
# /mo5TKhBtQoi6Y4h/TAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUxqxjiTdFbMaeWXUnOyqyDMHg
# o0cwDQYJKoZIhvcNAQEBBQAEggEA1F5Q0L3WOgrhfqUBj0GtJv1UW14wG+jJZ0wf
# Rt9YzkPbaF5whlQh5THDLAP6bNwB+HvOu912/WLXZlpONWRdBLOIyd7nuKHuW1w/
# ibtohcCJbp6qxKR5SRJ+PSGZxQBU0KHu4lQ9L4DiBuHncwDCrMfSRoAzHLFMGORS
# bGTzDCX4ALwjSvUDF2tRMlRkcWJK/JYfktwGks/8bKEt2ELJxgfuaTghmFneLlQM
# 5LsyljTy1AhngeEEGzyFFQ1WgPStzIaxOkIaDSdiLDHbuR4155ShrtoxtX4Ixs6d
# JNM1BiEiwzho6MNVNJl+uwp0WpLNKJbm6zcO0wL9V0Mz35hU3Q==
# SIG # End signature block
