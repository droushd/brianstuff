Param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$override, 
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$dateAfter
  )

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ErrorActionPreference = "SilentlyContinue"
Function Get-MyI {$MyInvocation}
Function global:Write-UpdateScreen ($message) {Write-Output "[$(Get-Date -format "H:mm:ss")] $message"}

function Publish-AzITSTableRowPrivate {
    <# 
        .SYNOPSIS
        Sends a hash to an Azure Log
        .DESCRIPTION 
        This function accepts a hash/dict and a table name,
        and sends it to a table in ITS All storage account. 
        Includes error handling in the table itself (not a separate error logging table)
    #>
    Param(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$logentry,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$table,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$iserror,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$isdiagnostics,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$catch,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$tableEndpoint,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$SAS,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$isfinally
      )
      Process
      {
        # this is the storage acount URL:
        if (-not($tableEndpoint)) {$tableEndpoint = 'https://itsall.table.core.windows.net/'}
        # this provides authorization to upload: expires 2029
        if (-not($SAS)) {$SAS = "?sv=2018-03-28&ss=bfqt&srt=o&sp=wau&se=2029-05-08T02:56:43Z&st=2019-05-07T18:56:43Z&spr=https&sig=GIpgKTGgY0xDwGU%2FGVdkhj8Bd%2FY9zvDHdEDyb8e7oV0%3D"}
  
        # this section allows skipping the logging if it's called the first time during a finally statement
        if (-not($AzITSTableRow)) {$global:AzITSTableRow = 0}
        $AzITSTableRow += 1
        if ($AzITSTableRow -eq 1 -And $isfinally) {return}
  
        # $zLogEntry = $logentry | convertto-json -Depth 9
        if ($catch) {
            # Overwrite the incoming 
            if ($null -ne $($logentry['PartitionKey'])) {$PartitionKey = $logentry['PartitionKey']}
            $logentry = New-Object 'system.collections.generic.dictionary[string,string]'
            $logentry['PartitionKey'] = $PartitionKey
            # $logentry['zLogEntry'] = $($zLogEntry.tostring()).substring(1,100)
            $logentry['zException'] = $catch.Exception.message
            $logentry['zScriptStackTrace'] = $catch.scriptstacktrace   
            $callStack = Get-PSCallStack
            $logentry['zScriptLineNumber'] = $callStack.InvocationInfo.ScriptLineNumber
            # $logentry['zPSCallStack'] = $callStack | ConvertTo-Json -Depth 9            
            # try{stop-transcript|out-null} catch [System.InvalidOperationException]{}
            $logentry['zTranscript'] = Get-Content $isdiagnostics | Select-Object -last 200 | Out-String
            # Write-Output "Error Condition: $($catch.scriptstacktrace)"
            # Write-Output "Error Condition: $($catch.Exception.message)"         
        }
  
        # these key fields are required: 
    #	partition keys are unique across the table; 
  
        if ($logentry.gettype().name -match 'PSCustomObject') {
            $ht2 = @{}
            $logentry.psobject.properties | & { process { 
            if($_.Value.length -lt 1){$newvalue=''}
            else{$newvalue= $_.Value}
            # this cleans variable names from asset panda: Department (User) becomes just Department
            $newname = (($_.Name) -replace('\(([^\)]+)\)', '')) -replace('\(|\)|#| ',"") 				
            $ht2[$newname] = $newvalue
            } }
            try { 
                $logentry = New-Object 'system.collections.generic.dictionary[string,string]'
                $logentry = $ht2
            }
            catch {$ht2;$_.scriptstacktrace;$_;break}
        } 
        else {
        # this is to avoid dictionary keys that start with a number (illegal char in Azure Table)
            $deletekey = @()
            $logentry.GetEnumerator() | ForEach-Object {if ($_.key -match "^[0-9]") {$deletekey += $_.key}}
            $deletekey | ForEach-Object {
                $logentry["a_$($PSItem)"]=$logentry["$PSItem"];
                $logentry.remove($PSITem) | Out-Null}
        }
        if ($isdiagnostics) {
            $logentry['zTranscript'] = Get-Content $isdiagnostics | Out-String
            $callStack = Get-PSCallStack
            $logentry['zScriptLineNumber'] = $callStack.InvocationInfo.ScriptLineNumber
        }
        if ($null -eq $($logentry['PartitionKey'])) {
            $PartitionKey = "$([System.Net.Dns]::GetHostName())"
            $logentry['PartitionKey'] = "$([System.Net.Dns]::GetHostName())"
        }
        else {
            $PartitionKey = $logentry['PartitionKey']
        }
        if ($null -eq $($logentry['RowKey'])) {
            $RowKey = Get-Date -Format o
            $logentry['RowKey'] = Get-Date -Format o
        }
        else {
            $RowKey = $logentry['RowKey']
        }
  
        $URI = $tableEndpoint + $table + "(PartitionKey='$PartitionKey', RowKey='$Rowkey')" + $SAS
        $RequestBody = ConvertTo-Json -InputObject $logentry -depth 9 -ErrorAction SilentlyContinue
        $EncodedRequestBody = [System.Text.Encoding]::UTF8.GetBytes($RequestBody)
        $RequestHeaders = @{
            "x-ms-date" = (Get-Date -Format r);
            "x-ms-version" = "2016-05-31";
            "Accept-Charset" = "UTF-8";
            "DataServiceVersion" = "3.0;NetFx";
            "MaxDataServiceVersion" = "3.0;NetFx";
            "Accept"    = "application/json;odata=nometadata";
            "ContentLength" = $EncodedRequestBody.Length
            }
  
        try 
		{
			$ProgressPreference = 'SilentlyContinue' 
            Invoke-WebRequest -Method PUT -Uri $URI -Headers $RequestHeaders -Body $EncodedRequestBody -ContentType "application/json" -UseBasicParsing #| foreach {($_.StatusCode)}
			$ProgressPreference = 'Continue' 
        }
        
        catch [System.Net.WebException] { 
          Write-Verbose "An exception was caught: $($_.Exception.Message)"
          $_.Exception.Response
        }
    }        
  } # End Function Publish-AzITSTableRowPrivate


try {
	$runtime =  [system.diagnostics.stopwatch]::StartNew()
	# $perfchecks = New-Object System.Collections.ArrayList($null)  #New-Object PSCustomObject
	# $private:maintenancewindow = (get-date).Hour -lt 8 -or (get-date).Hour -gt 20 -or (Get-Date).DayOfWeek.value__ -ge 6
	$private:ScriptName = "IntuneEventsMain.ps1"
	# $private:itsallTable = "EventsAllErrors"
	$private:transcript = $("$env:temp\$ScriptName" + $(Get-Date | ForEach-Object {$_.ticks}) + ".txt") -replace ".ps1","_" 
	Start-Transcript -Path $transcript  -IncludeInvocationHeader | ForEach-Object {Write-UpdateScreen $_}
	$ErrorActionPreference = "SilentlyContinue"
	# $jobdonepath = "C:\Penn Law ITS\Scripts\IntuneSoftwareUpdates.txt"

	if ($PSCommandPath -match 'droush') {
		Write-UpdateScreen "Publishing updated version of script first"
		$ProgressPreference = 'SilentlyContinue' 
		Publish-AzITSAll .\$ScriptName
		$ProgressPreference = 'Continue' 
	}


	$Win10ITSexists_current = Get-ChildItem "C:\Program Files\*\Modules\Win10ITS\*" | Sort-Object LastWriteTime -Descending | Select-Object -first 1 #| Where-Object {[version]$_.name -gt $Win10ITSexists_min} | ForEach-Object {$_.name}
	$win10itsExists = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue
	$win10itsImported = "C:\Program Files\*\Modules\Win10ITS\$Win10ITSexists_current\win10its.psd1"
	if ($Win10ITSexists_current) {
        if (-not$win10itsExists) {
			Write-UpdateScreen "ERROR: Win10ITS exists but isn't importing"
			Import-Module $win10itsImported
			$win10itsExists = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue | ForEach-Object {$_.version}
			Write-UpdateScreen "ERROR: Win10ITS manually importing ($Win10ITSexists_current)"
            try {$private:hw = Get-Inven -basic -ordered $ordered}
            catch {$private:hw = New-Object 'system.collections.generic.dictionary[string,string]'}
            $hw['Win10ITS'] = "$Win10ITSexists_current;$false"
		}
        else {
            Write-UpdateScreen "using Get-Inven"
            try {$private:hw = Get-Inven -basic -ordered $ordered}
            catch {$private:hw = New-Object 'system.collections.generic.dictionary[string,string]'}
            $hw['Win10ITS'] = "$Win10ITSexists_current;$true"
			Receive-PennLawITS
        }

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
	$hw['RowKey'] =  "$([System.Net.Dns]::GetHostName())"

	$taskname = "PennLawIntuneBitlocker"
	$tasknameexists = Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue
	if (-not$tasknameexists) {
		schtasks.exe /create /f /tn "PennLawIntuneBitlocker" /ru SYSTEM /sc ONLOGON /tr "powershell -executionpolicy bypass -command {Backup-Bitlocker} -noprofile" | ForEach-Object {Write-UpdateScreen $PSItem}
	}


	$taskname = "PennLawIntuneEventsMain"
	$tasknameexists = Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue
	schtasks.exe /create /f /tn "PennLawIntuneEventsMain" /ru SYSTEM /sc ONSTART /tr "powershell -executionpolicy bypass -file 'C:\Penn Law ITS\Scripts\IntuneEventsMain.ps1' -noprofile" | ForEach-Object {Write-UpdateScreen $PSItem}
	$settings = New-ScheduledTaskSettingsSet
    $settings.ExecutionTimeLimit = "PT5M"
	$settings.stopifgoingonbatteries = $false
	$settings.DisallowStartIfOnBatteries = $false
	$Settings.CimInstanceProperties.Item('MultipleInstances').Value = 3   # 3 corresponds to 'Stop the existing instance'
    $taskname = "PennLawIntuneEventsMain"
	Get-ScheduledTask | Where-Object {$_.taskname -match $taskname} | ForEach-Object {Set-ScheduledTask -TaskName $_.taskname -Settings $settings} | ForEach-Object {Write-UpdateScreen "Updated: $taskname ; state $($_.state)"}

	$taskname = "PennLawIntuneEventsDaily"
	$tasknameexists = Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue
	schtasks.exe /create /f /tn $taskname /ru SYSTEM /sc DAILY /st 02:00 /du 0023 /ri 360 /tr "powershell -executionpolicy bypass -file 'C:\Penn Law ITS\Scripts\IntuneEventsMain.ps1' -noprofile" | ForEach-Object {Write-UpdateScreen $PSItem }
	$settings = New-ScheduledTaskSettingsSet
    $settings.ExecutionTimeLimit = "PT5M"
    $settings.waketorun = $true
	$settings.stopifgoingonbatteries = $false
	$settings.DisallowStartIfOnBatteries = $false
	$Settings.CimInstanceProperties.Item('MultipleInstances').Value = 3   # 3 corresponds to 'Stop the existing instance'
	Get-ScheduledTask | Where-Object {$_.taskname -match $taskname} | ForEach-Object {Set-ScheduledTask -TaskName $_.taskname -Settings $settings} | ForEach-Object {Write-UpdateScreen "Updated: $taskname ; state $($_.state)"}

	if ($DateAfter) {
		
		$DateAfter = (Get-Date).AddDays($forceNegative)
	}
    else {$DateAfter = (Get-Date).AddDays(-7)}

	# $DateAfter = (Get-Date).AddDays(-7)


	$ReliabilityStabilityMetrics = Get-CimInstance -ClassName win32_reliabilitystabilitymetrics -ErrorAction SilentlyContinue #| Select-Object PSComputerName, SystemStabilityIndex, TimeGenerated
	# $y = $ReliabilityStabilityMetrics.TimeGenerated | foreach {Get-Date $_ | foreach {[double]$_.dayofyear}}
	# $x = $ReliabilityStabilityMetrics.SystemStabilityIndex | foreach {[double]$PSItem}

	if ($null -ne $ReliabilityStabilityMetrics.SystemStabilityIndex) {
		$hw['Reliability'] = $ReliabilityStabilityMetrics.SystemStabilityIndex | Measure-Object -max -min -average | Select-Object maximum, @{ n="minimum"; e={[math]::round( $_.minimum, 2 )}}, @{ n="average"; e={[math]::round( $_.average, 2 )}} |convertto-json
	}

	###
	###
	### this line takes 2 minutes!!
	# $hw['AppCrash'] =  Get-CimInstance -ClassName win32_reliabilityRecords -filter "SourceName = 'Application Error'" -ErrorAction SilentlyContinue | Group-Object productname | Select-Object name, count | convertto-json
	### this line takes 2 minutes!!
	###
	###

	try {
		$hw['AppCrash2'] = Get-WinEvent -FilterHashtable @{'providername' = 'Windows Error Reporting';starttime=$DateAfter;Id=1001 } -ErrorAction SilentlyContinue | 
		Select-Object TimeCreated,@{n='App';e={$_.Properties[5].value}}| Group-Object -Property App | Select-Object -Property Name,Count| Sort-Object -Property Count -Descending | convertto-json	
	}
	catch {$hw['AppCrash2'] = $null}
	# Import-module C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Diagnostics\Microsoft.PowerShell.Diagnostics.psd1
	Write-UpdateScreen "Reliability: $($ReliabilityStabilityMetrics.count); AppCrash: (TK)"

	function Format-XML ([xml]$xml, $indent=2)
	{
		<#
		.Synopsis
		Format XML text as a readable string
	
		.Description
		This function accepts XML objects and outputs formatted strings.
	
		.Example
		# take in outerxml and indent 2
		Format-Xml $fan.DellDiag.outerxml 2  
	
		#>
		$StringWriter = New-Object System.IO.StringWriter
		$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
		$xmlWriter.Formatting = "indented"
		$xmlWriter.Indentation = $Indent
		$xml.WriteContentTo($XmlWriter)
		$XmlWriter.Flush()
		$StringWriter.Flush()
		Return $StringWriter.ToString()
	}
	

	# $AllDrivers[0].message -split " " | where {$_ -match "\w+\\\w+"}
	$driverlist = Get-AllDrivers
	$driverlist_hash = @{}
	$driverlist | ForEach-Object {$driverlist_hash["$($_.DeviceID)"]=$PSItem}
	try {$AllDrivers = Get-WinEvent -FilterHashTable @{ LogName = "Microsoft-Windows-Kernel-PnP/Device Management";StartTime = $DateAfter} -ErrorAction SilentlyContinue | Where-Object {$_.leveldisplayname -notmatch "Information"}} catch {}
	$AllDriversEdit = $AllDrivers | ForEach-Object { 
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		$deviceID = $_.message -split " " | Select-Object -skip 1 | Select-Object -first 1 #where {$_ -match "\w+\\\w+"}
		if ($deviceID) {
			$driverinfo = $driverlist_hash[$deviceID] 
			if ($driverinfo) {
				$devicename = $driverinfo.DeviceName
				$driverversion = $driverinfo.'DriverVersion-Value'
			}
		}
		[PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			Name = $devicename
			OS = $($hw['OS'])
			Model = $($hw['Model'])
			Version = $driverversion
			z_ID = $PSItem.id 
			z_Message = $PSItem.Message
			z_Event = Format-XML $PSItem.toxml() 2
			
			# Schedtask = $($hw['z_TaskinProgress'])
		}
	}
	# $AllDriversEdit | ForEach-Object {Publish-AzITSTableRowPrivate -logentry $PSItem -table 'EventsDrivers'} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload AllDrivers: $($_.Name); qty $($_.count)"}
	$AllDriversEdit | ForEach-Object {Publish-AzITSTableRow -logentry $PSItem -table 'EventsDrivers'} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload AllDrivers: $($_.Name); qty $($_.count)"}

	# https://blogs.technet.microsoft.com/askcore/2008/10/31/how-to-debug-kernel-mode-blue-screen-crashes-for-beginners/
	try {$AllErrors = Get-WinEvent -FilterHashTable @{ LogName = "Application";StartTime = $DateAfter} -ErrorAction SilentlyContinue  | Where-Object {$_.id -match "41|60" -or $_.providername -match "Windows Error"}} catch {}
	# Write-UpdateScreen "All Events Found: $($BSOD.count)"
	$AllErrorsEdit = $AllErrors | ForEach-Object { 
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		$isbluescreen = $PSItem.message -match "Bluescreen"
		if ($_.id -match 1001) {
			$x = 0
			$rc1 = @{}
			$filename = $_ | Select-Object -expand properties | ForEach-Object {$_.value} | Select-Object -first 15 | ForEach-Object {
				$name = 'P{0:d2}' -f [int]$x
				$rc1[$name] = $_
				$x += 1
			}
			$rc1['RowKey'] = $rowkey
			$rc1['PartitionKey'] = $env:COMPUTERNAME      
			$rc1['AzureADUsers'] = $($hw['AzureADUsers'])
			$rc1['IntuneUPN'] = $($hw['IntuneUPN'])
			$rc1['BSOD'] = $isbluescreen
			$rc1['z_Message'] = $PSItem.Message
			$rc1['z_Event'] = Format-XML $PSItem.toxml() 2
			Publish-AzITSTableRowPrivate -logentry $rc1 -table 'EventsAppCrash' | Out-Null
		}
		[PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			BSOD = $isbluescreen
			z_ID = $PSItem.id 
			Message = $PSItem.Message
			z_Event = Format-XML $PSItem.toxml() 2
			# z_Scriptname = $scriptname
			Schedtask = $($hw['z_TaskinProgress'])
		}
		
	}
	$AllErrorsEdit | ForEach-Object {Publish-AzITSTableRowPrivate -logentry $PSItem -table 'EventsAllErrors'} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload AllErrors: $($_.Name); qty $($_.count)"}

	# $BSOD | Where-Object {$_.message -match "Bluescreen"} | Measure-Object | ForEach-Object {Write-UpdateScreen "BSOD Events Found: $($_.count)"}
	$BSOD = $AllErrors | Where-Object {$_.message -match "Bluescreen"} | ForEach-Object { 
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		[PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			z_ID = $PSItem.id 
			Message = $PSItem.Message
			z_Event = Format-XML $PSItem.toxml() 2
			Report = $PSItem.message.Split("`n") | Where-Object {$_ -match 'ReportArchive'} | ForEach-Object {Get-Childitem $_.replace("\\?\","").trim()} | Select-Object -first 1 | ForEach-Object {get-content $_.fullname} | out-string
			z_Scriptname = $scriptname
			Schedtask = $($hw['z_TaskinProgress'])
		}
	} 
	$BSOD | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table 'EventsBSOD'} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload BSOD: $($_.Name); qty $($_.count)"}

	if (get-date | ForEach-Object {($_.day % 2) -eq 0}) {
		$mdmevents = Get-WinEvent -FilterHashtable @{StartTime=$((Get-Date).AddDays(-3));logname='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'} | 
        Where-Object {$_.message -notmatch 'MDM Session: OMA-DM client started|OMA-DM session started|OMA-DM session Loaded|OMA-DM session Handled|OMA-DM session Init'} | 
        Group-Object message |  ForEach-Object {$_.group | Sort-Object timecreated -descending | Select-Object -first 1 } 
		$mdmevents | & { process {$_ | Add-Member -type NoteProperty -name TimeCreated -value $(Get-Date $PSItem.timecreated -format s) -Force} }	
		$mdmevents = $mdmevents | Group-Object timecreated | ForEach-Object {
			$_.group | ForEach-Object {
				Clear-Variable -name rowkey -erroraction silentlycontinue
				$rowkey = "$(Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue)_$x"
				[PSCustomObject]@{
					RowKey = $rowkey
					PartitionKey = $env:COMPUTERNAME      
					A_AzureADUsers = $($hw['AzureADUsers'])
					A_IntuneUPN = $($hw['IntuneUPN'])
					A_ID = $PSItem.id 
					A_Level = $_.LevelDisplayName
					Message = $PSItem.Message
					Z_TimeCreated = $_.TimeCreated
				}
				
			}
		}  
		$mdmevents | ForEach-Object {Publish-AzITSTableRowPrivate -logentry $PSItem -table 'EventsMDM' }| ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload MDM: $($_.Name); qty $($_.count)"}
		
		$mdmEventsExtended = Get-MDMEvents -DateAfter $((get-Date).adddays(-7)) | Group-Object RowKey | ForEach-Object {
			$group = $_.group
			$x = 0
			$group | ForEach-Object {
				$PSItem.RowKey = "$($PSItem.RowKey)_$x"
				$x++
				$PSItem
			}
		}
		$mdmEventsExtended | ForEach-Object { Publish-AzITSTableRow -logentry $PSItem -table 'EventsMDMExtended' } | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload MDMEventsExtended: $($_.Name); qty $($_.count)"}

		$MDMLog = Get-LogProperties 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug' 
		$MDMLog.Enabled = $true
		Set-LogProperties -LogDetails $MDMLog -Force
		
		$MDMLog = Get-LogProperties 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' 
		$MDMLog.MaxLogSize = 40MB
		Set-LogProperties -LogDetails $MDMLog
	}


	$shutdown = Get-WinEvent -FilterHashtable @{StartTime=$DateAfter;logname='System'; id=1074} -ErrorAction SilentlyContinue | ForEach-Object { 
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		[PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			z_ID = $PSItem.id 
			User = $PSItem.Properties[6].Value
			Process = $PSItem.Properties[0].Value
			Action = $PSItem.Properties[4].Value
			Reason = $PSItem.Properties[2].Value
			ReasonCode = $PSItem.Properties[3].Value
			Comment = $PSItem.Properties[5].Value
			z_Scriptname = $scriptname
			Schedtask = $($hw['z_TaskinProgress'])
		}
	} 
	$shutdown | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table EventsShutdown}  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsShutdown: $($_.Name); qty $($_.count)"}
	
	$event_hash = @{12='startup';13='shutdown';41='startup';6005='startup';6008='shutdown'}
	$Filter = @{
		Logname = 'System'
		ID = 12,13,41,6005,6008
		StartTime =  [datetime]::Today.AddDays(-7)
		EndTime = [datetime]::Today
 	}
 	$otherreboots = Get-WinEvent -FilterHashtable $Filter -erroraction silentlycontinue | Where-Object {$_.ProviderName -match 'Microsoft-Windows-Kernel-General' } | ForEach-Object { 
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		[PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			z_ID = $PSItem.id 
			User = $null #$PSItem.userid.tostring()
			Process = $null
			Action = $event_hash[$($PSITem.id)] 
			Reason = $null
			ReasonCode = $null
			Comment = $PSItem.message
			z_Scriptname = $scriptname
			Schedtask = $($hw['z_TaskinProgress'])
		}
	} 
	$otherreboots | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table EventsShutdown}  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload OTHER EventsShutdown: $($_.Name); qty $($_.count)"}

	$MSIInstallers = Get-WinEvent -FilterHashtable @{StartTime=$DateAfter;logname='Application'} -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -match "msiInstaller"} |
		Where-Object {$_.message -notmatch 'Windows Installer reconfigured the product'} |
		Where-Object {$_.message -match "Product:|Product Name:|restart"}
		# Write-UpdateScreen "Get NonWindows Updates and Installs (count): $($MSIInstallers.count); only send last 7 days"
	$MSIInstallers | ForEach-Object { 
		$pattern = "Product: (.*?) -"
		Clear-Variable -name rowkey -erroraction silentlycontinue
		$rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
		$row = [PSCustomObject]@{
			RowKey = $rowkey
			PartitionKey = $env:COMPUTERNAME      
			AzureADUsers = $($hw['AzureADUsers'])
			IntuneUPN = $($hw['IntuneUPN'])
			Title = $PSItem.message
			InstalledOn = (Get-Date -Date $($PSItem.TimeCreated) -format "M/dd/yyyy H:mm:ss")
			Product = [regex]::match($PSItem.message, $pattern).Groups[1].Value
			z_ID = $PSItem.id
			z_Properties = $PSItem | Select-Object -Expand Properties | Out-String
			z_Status = $($PSItem.Properties[2].Value.replace('(NULL)',''))
			z_ReasonCode = $($PSItem.Properties[3].Value.replace('(NULL)',''))
			z_Comment = $($PSItem.Properties[5].Value.replace('(NULL)',''))
			z_scriptname = $scriptname
		}
		Publish-AzITSTableRowPrivate -logentry $row -table 'UpdatesMSI' 
	} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload MSI: $($_.Name); qty $($_.count)"}

	$cltr = Get-Command -Name Convert-LastTaskResult -ErrorAction SilentlyContinue
	$taskresults = New-Object System.Collections.ArrayList($null) 
	$taskinfo = Get-ScheduledTask | Where-Object {$_.taskpath -eq "\"} | Get-ScheduledTaskInfo #
	$taskinfo | ForEach-Object {
		$taskinfo_result = $PSItem
		try {
			if ($null -ne $taskinfo_result.NextRunTime) {$NextRunTime = $(Get-Date $_.NextRunTime -format s -erroraction silentlycontinue)}
			else {$NextRunTime = $null}
		}
		catch {$NextRunTime = $null}
		try {
			if ($null -ne $taskinfo_result.LastRunTime) {$LastRunTime = $(Get-Date $_.LastRunTime -format s -erroraction silentlycontinue)}
			else {$LastRunTime = $null}
		}
		catch {$LastRunTime = $null}
		try {
			if ($null -ne $_.LastTaskResult -And $_.LastTaskResult -As [double]) {
				Clear-Variable -Name Result -ErrorAction SilentlyContinue
				$result = switch ($_.LastTaskResult) {
					{$_ -eq 0} {net helpmsg 0;break}
					{$_ -eq 1} {net helpmsg 1;break}
					{$_} {'{0:x}' -f $_ | ForEach-Object {$_.Substring($_.Length - 4)} | ForEach-Object {
						$number = $([uint32]"0x$PSItem")
						if ($number -match "65531|60932") {"err"}
						else {
							try{ net helpmsg $number }
							catch {"err"}
						}
					}}
				}  
				$rc1 = [PSCustomObject]@{
					RowKey = $_.TaskName
					PartitionKey = $env:COMPUTERNAME
					NumberOfMissedRuns = $_.NumberOfMissedRuns
					NextRunTime = $NextRunTime
					LastTaskResult = $result[1]
					LastRunTime = $LastRunTime
				}
				$taskresults.add($rc1) | Out-Null
			}
			else {
				$rc1 = [PSCustomObject]@{
					RowKey = $_.TaskName
					PartitionKey = $env:COMPUTERNAME
					NumberOfMissedRuns = $_.NumberOfMissedRuns
					NextRunTime = $NextRunTime
					LastTaskResult = $_.LastTaskResult
					LastRunTime = $LastRunTime
				}
				$taskresults.add($rc1) | Out-Null
			}
		}
		catch {
			Clear-Variable -Name cltr_result -ErrorAction SilentlyContinue
			if ($null -ne $cltr) {$cltr_result = Convert-LastTaskResult $taskinfo_result.LastTaskResult}
			if ($null -eq $cltr_result) {$cltr_result = $taskinfo_result.LastTaskResult}
			$rc1 = [PSCustomObject]@{
				RowKey = $taskinfo_result.TaskName
				PartitionKey = $env:COMPUTERNAME
				NumberOfMissedRuns = $taskinfo_result.NumberOfMissedRuns
				NextRunTime = $NextRunTime
				LastTaskResult = $cltr_result
				LastRunTime = $LastRunTime
			}
			$taskresults.add($rc1) | Out-Null
		}

	}
	# Write-UpdateScreen "Scheduled Task Results: $($taskresults.count)"
	$taskresults | ForEach-Object {Publish-AzITSTableRowPrivate -logentry $PSItem -table 'EventsSchedTasks'} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload SchedTasks: $($_.Name); qty $($_.count)"}

    try {
		$dellculog_file = "C:\ProgramData\dell\UpdateService\Log\Activity.log"
		$dellcuLog = Get-ChildItem -ErrorAction SilentlyContinue "C:\ProgramData\dell\UpdateService\Log\Activity.log" | ForEach-Object {[xml](Get-Content $PSItem.fullname -ErrorAction SilentlyContinue)}
	}
	catch {
		$trapDell = $_.Exception
	}
    if ($dellcuLog) {
		$x = 0
		$getlastcheck = $dellcuLog.logentries.logentry | Where-Object {$_.source -match 'update.update'}  | Select-Object -last 1 | Where-Object {$_.timestamp.length -gt 1} | ForEach-Object {Get-date $_.timestamp -format s}
		$getlastupdate = $dellcuLog.logentries.logentry | Where-Object {$_.source -match 'update.update' -And $_.message -match 'Applying updates'}  | Select-Object -last 1 | Where-Object {$_.timestamp.length -gt 1} | ForEach-Object {Get-date $_.timestamp -format s}
		$dellcuversion = get-sw | Where-Object {$_.displayname -match "Dell Command(.*)Update"} | ForEach-Object {$_.displayversion}
      	$dellupdates = $dellcuLog.logentries.logentry | Where-Object {$_.source -match 'Operations.UpdateOperation.Install'} | ForEach-Object {  
				try {
					$message = $_.message
					$date = $(Get-Date $_.timestamp -format s)
					if ($message -as [string] -And $date -As [Datetime]) {
						$update = $_.message.replace("Installing '","") -replace "' \[\w+\]",""
						$isOK = $null -ne $update -And $update.length -gt 1 -And $update -notmatch "Cannot convert" -And $date -gt $((Get-Date).AddDays(-30))
						if ($isOK) {
							[PSCustomObject]@{
								PartitionKey = "$([System.Net.Dns]::GetHostName())"
								RowKey = $(Get-Date $_.timestamp -format s)
								Install = $update
								IntuneUPN = $hw['IntuneUPN']
								LastCheck = $getlastcheck
								LastUpdate = $getlastupdate
								Version = $dellcuversion
							} 
						}
					}
				}
				catch {
					# Write-UpdateScreen "Error Uploading DellCU: $($x++)"
					$_
				}
		}
		$dellupdates | ForEach-Object {Publish-AzITSTableRowPrivate -logentry $psitem -table UpdatesDellCU  } | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload DellCU: $($_.Name); qty $($_.count)"}
    }

	$WLAN_Report = "C:\ProgramData\Microsoft\Windows\WlanReport"
	$WLAN_Report_date = Get-ChildItem $WLAN_Report | Sort-Object lastwritetime -Descending|  Select-Object -first 1 | ForEach-Object {get-date $_.lastwritetime -format s}
	if ($WLAN_Report_date) {
		$WLAN_Report_date_today = get-date $WLAN_Report_date | Where-Object {$_.date -ge (get-date).date}
	}
	if ($null -eq $WLAN_Report_date_today -or $null -eq $WLAN_Report_date) {
		netsh wlan show wlanreport
		$wlan = [xml](Get-Content   C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.xml -ErrorAction SilentlyContinue)
		$fields = @("success","guid","interface","driver","mode","profile","ssid","bss","disconnect","duration")
		$wlanreport = $wlan.WlanReport.WlanEvents.wlansession  | ForEach-Object {
			$session = $_ 
			$PSItem.wlanevent | ForEach-Object {
				$event = $_ 
				$fields | ForEach-Object {
					$fieldname = $PSItem.trim()
					$event | Add-Member -Name $fieldname -Value $session.$($fieldname) -MemberType NoteProperty -Force
				}
				$event
			} 
		}
		$wlanreport = $wlanreport | Group-Object EventTime | ForEach-Object {
			$x = 0	
			$group = $_
			$name = $group.name
			$group.group | ForEach-Object {
				$x += 1
				$PSItem | Add-Member -Name PartitionKey -Value $env:COMPUTERNAME -MemberType NoteProperty -Force
				$PSItem | Add-Member -Name RowKey -Value "$($name)_$($x)" -MemberType NoteProperty -Force
				$PSItem | Add-Member -Name OS -Value $($hw['OS']) -MemberType NoteProperty -Force
				$PSItem
			} 
		} 
		$allfields = @("success","guid","interface","driver","mode","profile","ssid","bss","disconnect","duration","Type","Error","UID","EventID","EventLevel","EventTime","EventMessage","PartitionKey","RowKey")
		$wlanreport | Select-Object $allfields | ForEach-Object {Publish-AzITSTableRow -logentry $psitem -table EventsWLAN} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "WLAN Events: $($_.name) $($_.count)"}
	
		$CabFile = Get-ChildItem C:\ProgramData\Microsoft\Windows\WlanReport\*.cab | ForEach-Object {$_.FullName}
		cmd.exe /c "C:\Windows\System32\expand.exe -F:* $CabFile $env:temp\wlanreport"
		try {
			$azstorage = Get-Command -Module Az.Storage
			if ($null -eq $azstorage) {Install-Module -Name Az.Storage -Force -Scope AllUsers -SkipPublisherCheck -erroraction SilentlyContinue }
			Import-Module Az.Storage -ea silentlycontinue
			Add-Type -Assembly 'System.IO.Compression.FileSystem'
			$filename = "$([System.Net.Dns]::GetHostName())_WlanReport.zip"
			$zipFilePath = "$env:temp\$filename"
			if (Test-Path $zipFilePath) {Remove-Item -Path $zipFilePath -Force}
			$zip = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'create')
			$zip.Dispose()
			$compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
			$zip = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'update')
			Get-ChildItem "$($WLAN_Report)*" | Sort-Object lastwritetime -Descending | Select-Object -first 100 | ForEach-Object {
				try { 
					[IO.File]::OpenWrite($PSitem.FullName).close() 
					[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $PSitem.FullName, (Split-Path $PSitem.FullName -Leaf), $compressionLevel) | OUt-Null
				}
				catch {}    
			} 
			$zip.Dispose()  
			$StorageContext = New-AzStorageContext -StorageAccountName itsfree -StorageAccountKey hbF7V2hEDfLNANYrTnAI2Ld84+nArSmlHD290kpMse0ge5RisSNc5dnK0XbpHK23ylpEtR+U9hBP9eqk0Gm/Cg== 
			Set-AzStorageFileContent -context $storagecontext -sharename intunetranscripts -source $zipFilePath -path $filename -Force -ErrorAction SilentlyContinue                
			Write-Output "[$(Get-Date -format "H:mm:ss")] SUCCESS: Uploading Intune Script Logs to Azure ITSFREE"
		}
		catch {
			Write-Output "[$(Get-Date -format "H:mm:ss")] FAILED: Uploading Intune Script Logs to Azure ITSFREE"
		}
	}

	$x =0
	$eventsTeams = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Teams\logs.txt" | ForEach-Object {
		$logfile = Get-Content $_.fullname
		$username = $($_.fullname) -split '\\' | Select-Object -skip 2 | Select-Object -first 1
		$FileSize = Get-ChildItem $_.fullname | ForEach-Object {$_.length/1mb}
		$logfile |  ForEach-Object {
			$item = $PSItem
			$x += 1
			try {
				$date = $item -split "GMT" | Select-Object -first 1 | ForEach-Object {get-date $_ -format s}
				$id = [regex]::Match($item,"\<.*?\>") | ForEach-Object {$_.value}
				$type = $item -split "--" | Select-Object -skip 1 | Select-Object -first 1
				$description = $item -split "--" | Select-Object -last 1
				$iscrash = $description -match 'crashed'
				if ($iscrash) {$flag = "Crash"}
				else {$flag = $null}
				$repeat = $false
			}
			catch {
				$description = $item
				$repeat = $true
			}
			try {
				[PSCustomObject]@{
					Date = $date
					Repeat = $repeat
					Id = $id -replace "<|>",""
					Type = $type.trim()
					Flag = $flag
					Event = $description.trim()
					PartitionKey = "$([System.Net.Dns]::GetHostName())"
					RowKey = $date
					IntuneUPN = $hw['IntuneUPN']
					Username = $username
					Filesize = $filesize
				}
			}
			catch {Write-ITSHost "Error: $x";$_}
		}
	} | Where-Object {$_.type -match "warning|error"}  # this skips events with type Event or Info
	$eventsteams | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table EventsTeams}  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsTeams: $($_.Name); qty $($_.count)"}

	$eventszoomfiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs" -filter "zoom_ts_memlog*" -recurse 
	$eventszoomfilesMB = $eventszoomfiles | Measure-Object length -sum | ForEach-Object {$_.sum/1mb}
	$eventszoom = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs" -filter "zoom_ts_memlog*" -recurse | ForEach-Object {
		$userprofile = $file -replace 'C:\\Users\\','' | ForEach-Object {$_ -split '\\'} | Select-Object -first 1
		$file = $_.FullName
		$errors = Get-Content $file | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match "ERROR"}
		$errors | ForEach-Object {
			$iserror = $_ -split "`t" | Where-Object {$_.trim() -eq 'error'}
			if ($iserror) {
				$columns = $_ -split "`t"
				try {
					$cleandate = $columns[0] -split ":" | Select-Object -last 1
					$date = Get-Date $($columns[0] -replace ":$cleandate","") -format s
				}
				catch{}
				[PSCustomObject]@{
					Date = $columns[0]
					Product = $columns[1]
					Line = $columns[2]
					Type = $columns[3]
					Message = $columns[4]
					RowKey = $date
					PartitionKey = $env:COMPUTERNAME
					z_IntuneUPN = $hw['IntuneUPN']
					z_IntuneDate = $hw['IntuneDate']
					z_Model = $hw['Model']
					z_OSBuild = $hw['OSBuild']
					z_OS = $hw['OS']
					z_UserProfile = $userprofile
					Files = "Files: $($eventszoomfiles); MB: $eventszoomfilesMB"
				}
			}
		} 
	}

	$eventszoom | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table EventsZoom}  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsZoom: $($_.Name); qty $($_.count)"}
	

	$ZoomErrorConstants = @"
	[{"Name":"MEETING_ERROR_SUCCESS","Error Code":"0","Description":"Start meeting successfully"},{"Name":"MEETING_ERROR_INCORRECT_MEETING_NUMBER","Error Code":"1","Description":"The meeting number is wrong"},{"Name":"MEETING_ERROR_TIMEOUT","Error Code":"2","Description":"Start meeting request timeout"},{"Name":"MEETING_ERROR_NETWORK_UNAVAILABLE","Error Code":"3","Description":"The network is unavailable"},{"Name":"MEETING_ERROR_CLIENT_INCOMPATIBLE","Error Code":"4","Description":"Zoom SDK version is too low"},{"Name":"MEETING_ERROR_NETWORK_ERROR","Error Code":"5","Description":"Network error"},{"Name":"MEETING_ERROR_MMR_ERROR","Error Code":"6","Description":"MMR server error"},{"Name":"MEETING_ERROR_SESSION_ERROR","Error Code":"7","Description":"Session error"},{"Name":"MEETING_ERROR_MEETING_OVER","Error Code":"8","Description":"Requested meeting already ended"},{"Name":"MEETING_ERROR_MEETING_NOT_EXIST","Error Code":"9","Description":"Meeting does not exist"},{"Name":"MEETING_ERROR_USER_FULL","Error Code":"10","Description":"The number of participants exceeds the upper limit"},{"Name":"MEETING_ERROR_NO_MMR","Error Code":"11","Description":"There is no MMR server available for the current meeting"},{"Name":"MEETING_ERROR_LOCKED","Error Code":"12","Description":"Meeting is locked"},{"Name":"MEETING_ERROR_RESTRICTED","Error Code":"13","Description":"Meeting is restricted"},{"Name":"MEETING_ERROR_RESTRICTED_JBH","Error Code":"14","Description":"Join meeting before the host is not allowed"},{"Name":"MEETING_ERROR_WEB_SERVICE_FAILED","Error Code":"15","Description":"Failed to request web service"},{"Name":"MEETING_ERROR_REGISTER_WEBINAR_FULL","Error Code":"16","Description":"The number of registers exceeds the upper limit of the webinar"},{"Name":"MEETING_ERROR_DISALLOW_HOST_REGISTER_WEBINAR","Error Code":"17","Description":"Registering the webinar with the host's email is not allowed"},{"Name":"MEETING_ERROR_DISALLOW_PANELIST_REGISTER_WEBINAR","Error Code":"18","Description":"Registering the webinar with the panelist's email is not allowed"},{"Name":"MEETING_ERROR_HOST_DENY_EMAIL_REGISTER_WEBINAR","Error Code":"19","Description":"The registration of the webinar is rejected by the host"},{"Name":"MEETING_ERROR_WEBINAR_ENFORCE_LOGIN","Error Code":"20","Description":"User needs to log in if the user wants to join the webinar"},{"Name":"MEETING_ERROR_EXIT_WHEN_WAITING_HOST_START","Error Code":"21","Description":"User leaves the meeting when waiting for the host to start"},{"Name":"MEETING_ERROR_INVALID_ARGUMENTS","Error Code":"99","Description":"Meeting is failed due to invalid arguments"},{"Name":"MEETING_ERROR_UNKNOWN","Error Code":"100","Description":"Unknown error. Please seek help on Zoom Developer Forum"}]
"@ | convertfrom-json
	$ZoomErrorConstants_hash = @{}
	$ZoomErrorConstants | ForEach-Object {$ZoomErrorConstants_hash[[int32]$($_.'Error Code')]=$_}
	# https://marketplace.zoom.us/docs/sdk/native-sdks/ionic/resource/error-codes/

	$CrashesZoom = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs\*"  -filter "crashrpt.xml" -recurse | ForEach-Object { 
		$userprofile = $file -replace 'C:\\Users\\','' | ForEach-Object {$_ -split '\\'} | Select-Object -first 1
		$file = $_.FullName
		[xml]$xml = get-content $file
		$props = $xml.crashrpt.customprops.prop
		# $propsNames = @("","App Start Time")
		$starttime = $props | Where-Object {$_.name -in 'app start time'} | ForEach-Object {$_.value}
		$VideoLaunchReason = $props | Where-Object {$_.name -in 'VideoLaunchReason'} | ForEach-Object {$_.value}
		[PSCustomObject]@{
			CrashGUID = $xml.crashrpt.CrashGUID
			ExceptionType = $xml.crashrpt.ExceptionType	
			ExceptionName = $ZoomErrorConstants_hash[[int32]$($xml.crashrpt.ExceptionType)] | ForEach-Object {$_.name}
			ExceptionDescription = $ZoomErrorConstants_hash[[int32]$($xml.crashrpt.ExceptionType)] | ForEach-Object {$_.Description}
			AppVersion = $xml.crashrpt.AppVersion
			User = $xml.crashrpt.User
			SystemTimeUTC = $xml.crashrpt.SystemTimeUTC
			StartTime = $starttime
			VideoLaunchReason = $VideoLaunchReason
			RowKey = $xml.crashrpt.SystemTimeUTC
			PartitionKey = $env:COMPUTERNAME
			z_IntuneUPN = $hw['IntuneUPN']
			z_IntuneDate = $hw['IntuneDate']
			z_Model = $hw['Model']
			z_OSBuild = $hw['OSBuild']
			z_OS = $hw['OS']
			z_OperatingSystem = $xml.crashrpt.OperatingSystem
			z_UserProfile = $userprofile
			XML = $(get-content $file | Out-String)
		}
	}
	$CrashesZoom | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table EventsZoomCrash}  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsZoomCrash: $($_.Name); qty $($_.count)"}
	# $eventszoomcrashfiles  = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs\*" -recurse
	Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs\*" -recurse -filter "*.dmp" | Where-Object {$(Get-date $_.lastwritetime ) -lt (Get-date).AddDays(-1)} | ForEach-Object {
		Remove-Item -Path $_.FullName -Force -Verbose
	}
	
	# $eventszoomfiles | where {$_.LastWriteTime -lt (get-date).adddays(-1)} | foreach {Remove-Item -path $_.FullName -Force}
	Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Zoom\logs" -filter "zoom_ts_memlog*" -recurse | Where-Object {$(Get-date $_.lastwritetime ) -lt (Get-date).AddDays(-1)} | ForEach-Object {
		Remove-Item -Path $_.FullName -Force -Verbose
	}

	# $tokenhash = @{
	# 	"%%1936" = "full"
	# 	"%%1937" = "elevated"
	# 	"%%1938" = "normal"
	# 	"1" = "full"
	# 	"2" = "elevated"
	# 	"3" = "normal"
	# }

	# https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
	# REMOVED "SID":"S-1-0-0","DisplayName":"Null SID"},
	$knownSIDS_JSON = '[{"SID":"S-1-1-0","DisplayName":"World"},{"SID":"S-1-2-0","DisplayName":"Local"},{"SID":"S-1-2-1","DisplayName":"Console Logon"},{"SID":"S-1-3-0","DisplayName":"Creator Owner ID"},{"SID":"S-1-3-1","DisplayName":"Creator Group ID"},{"SID":"S-1-3-2","DisplayName":"Creator Owner Server"},{"SID":"S-1-3-3","DisplayName":"Creator Group Server"},{"SID":"S-1-3-4","DisplayName":"Owner Rights"},{"SID":"S-1-4","DisplayName":"Non-unique Authority"},{"SID":"S-1-5","DisplayName":"NT Authority"},{"SID":"S-1-5-80-0","DisplayName":"All Services"},{"SID":"S-1-5-1","DisplayName":"Dialup"},{"SID":"S-1-5-113","DisplayName":"Local account"},{"SID":"S-1-5-114","DisplayName":"Local account and member of Administrators group"},{"SID":"S-1-5-2","DisplayName":"Network"},{"SID":"S-1-5-3","DisplayName":"Batch"},{"SID":"S-1-5-4","DisplayName":"Interactive"},{"SID":"S-1-5-5-?X-Y","DisplayName":"Logon Session"},{"SID":"S-1-5-6","DisplayName":"Service"},{"SID":"S-1-5-7","DisplayName":"Anonymous Logon"},{"SID":"S-1-5-8","DisplayName":"Proxy"},{"SID":"S-1-5-9","DisplayName":"Enterprise Domain Controllers"},{"SID":"S-1-5-10","DisplayName":"Self"},{"SID":"S-1-5-11","DisplayName":"Authenticated Users"},{"SID":"S-1-5-12","DisplayName":"Restricted Code"},{"SID":"S-1-5-13","DisplayName":"Terminal Server User"},{"SID":"S-1-5-14","DisplayName":"Remote Interactive Logon"},{"SID":"S-1-5-15","DisplayName":"This Organization"},{"SID":"S-1-5-17","DisplayName":"IIS_USRS"},{"SID":"S-1-5-18","DisplayName":"System"},{"SID":"S-1-5-19","DisplayName":"NT Authority (LocalService)"},{"SID":"S-1-5-20","DisplayName":"Network Service"},{"SID":"S-1-5-domain-500","DisplayName":"Administrator"},{"SID":"S-1-5-domain-501","DisplayName":"Guest"},{"SID":"S-1-5-domain-502","DisplayName":"krbtgt"},{"SID":"S-1-5-domain-512","DisplayName":"Domain Admins"},{"SID":"S-1-5-domain-513","DisplayName":"Domain Users"},{"SID":"S-1-5-domain-514","DisplayName":"Domain Guests"},{"SID":"S-1-5-domain-515","DisplayName":"Domain Computers"},{"SID":"S-1-5-domain-516","DisplayName":"Domain Controllers"},{"SID":"S-1-5-domain-517","DisplayName":"Cert Publishers"},{"SID":"S-1-5-root domain-518","DisplayName":"Schema Admins"},{"SID":"S-1-5-root domain-519","DisplayName":"Enterprise Admins"},{"SID":"S-1-5-domain-520","DisplayName":"Group Policy Creator Owners"},{"SID":"S-1-5-domain-553","DisplayName":"RAS and IAS Servers"},{"SID":"S-1-5-32-544","DisplayName":"Administrators"},{"SID":"S-1-5-32-545","DisplayName":"Users"},{"SID":"S-1-5-32-546","DisplayName":"Guests"},{"SID":"S-1-5-32-547","DisplayName":"Power Users"},{"SID":"S-1-5-32-548","DisplayName":"Account Operators"},{"SID":"S-1-5-32-549","DisplayName":"Server Operators"},{"SID":"S-1-5-32-550","DisplayName":"Print Operators"},{"SID":"S-1-5-32-551","DisplayName":"Backup Operators"},{"SID":"S-1-5-32-552","DisplayName":"Replicators"},{"SID":"S-1-5-32-554","DisplayName":"Builtin\\Pre-Windows 2000 Compatible Access"},{"SID":"S-1-5-32-555","DisplayName":"Builtin\\Remote Desktop Users"},{"SID":"S-1-5-32-556","DisplayName":"Builtin\\Network Configuration Operators"},{"SID":"S-1-5-32-557","DisplayName":"Builtin\\Incoming Forest Trust Builders"},{"SID":"S-1-5-32-558","DisplayName":"Builtin\\Performance Monitor Users"},{"SID":"S-1-5-32-559","DisplayName":"Builtin\\Performance Log Users"},{"SID":"S-1-5-32-560","DisplayName":"Builtin\\Windows Authorization Access Group"},{"SID":"S-1-5-32-561","DisplayName":"Builtin\\Terminal Server License Servers"},{"SID":"S-1-5-32-562","DisplayName":"Builtin\\Distributed COM Users"},{"SID":"S-1-5-32-569","DisplayName":"Builtin\\Cryptographic Operators"},{"SID":"S-1-5-32-573","DisplayName":"Builtin\\Event Log Readers"},{"SID":"S-1-5-32-574","DisplayName":"Builtin\\Certificate Service DCOM Access"},{"SID":"S-1-5-32-575","DisplayName":"Builtin\\RDS Remote Access Servers"},{"SID":"S-1-5-32-576","DisplayName":"Builtin\\RDS Endpoint Servers"},{"SID":"S-1-5-32-577","DisplayName":"Builtin\\RDS Management Servers"},{"SID":"S-1-5-32-578","DisplayName":"Builtin\\Hyper-V Administrators"},{"SID":"S-1-5-32-579","DisplayName":"Builtin\\Access Control Assistance Operators"},{"SID":"S-1-5-32-580","DisplayName":"Builtin\\Remote Management Users"},{"SID":"S-1-5-64-10","DisplayName":"NTLM Authentication"},{"SID":"S-1-5-64-14","DisplayName":"SChannel Authentication"},{"SID":"S-1-5-64-21","DisplayName":"Digest Authentication"},{"SID":"S-1-5-80","DisplayName":"NT Service"},{"SID":"S-1-5-80-0","DisplayName":"All Services"},{"SID":"S-1-5-83-0","DisplayName":"NT VIRTUAL MACHINE\\Virtual Machines"},{"SID":"S-1-16-0","DisplayName":"Untrusted Mandatory Level"},{"SID":"S-1-16-4096","DisplayName":"Low Mandatory Level"},{"SID":"S-1-16-8192","DisplayName":"Medium Mandatory Level"},{"SID":"S-1-16-8448","DisplayName":"Medium Plus Mandatory Level"},{"SID":"S-1-16-12288","DisplayName":"High Mandatory Level"},{"SID":"S-1-16-16384","DisplayName":"System Mandatory Level"},{"SID":"S-1-16-20480","DisplayName":"Protected Process Mandatory Level"},{"SID":"S-1-16-28672","DisplayName":"Secure Process Mandatory Level"}]' | ConvertFrom-Json
	$known_SIDS_hash = @{}
	$knownSIDS_JSON | ForEach-Object {
		$key = $PSItem.SID
		$value = $PSItem.DisplayName
		$known_SIDS_hash[$key] = $value
	}

	# $eventIDs = @(4688,4648, 4624);
	$DateAfter = (Get-Date).AddDays(-7)
	$msAfter = 86400000*7
	$XML = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= $msafter]] and EventData[Data[@Name='TokenElevationType']='%%1937']]
        </Select>
    </Query>
	</QueryList>"

	$Local_SIDS_hash = @{}
	Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue | ForEach-Object {
		$key = $PSItem.PSChildName
		$value = Split-Path $PSItem.profileimagepath -Leaf
		$Local_SIDS_hash[$key] = $value
	} 
	
	$PrivUsage = Get-WinEvent -FilterXml $XML -ErrorAction SilentlyContinue | ForEach-Object {
		$securityID = $PSItem.message -split "`n" | Where-Object {$_ -match "Security ID:(.*)"} | ForEach-Object {
			$SID = ($matches.1).trim()
			if ($null -ne $SID) {
				if ($SID -match "S-1-12|S-1-5") {
					$Local_SIDS_hash[$SID] 	
				}
				elseif ($SID -notmatch "S-1-0-0") {
					$known_SIDS_hash[$SID] 	
				}
			}
		} | Where-Object {$null -ne $_} | ForEach-Object {$_.replace("/","")} | convertto-json -compress
		$NewProcessName = $PSItem.message -split "`n" | Where-Object {$_ -match "New Process Name:(.*)"} | ForEach-Object {$($matches.1).trim()}
		$CreatorProcessName = $PSItem.message -split "`n" | Where-Object {$_ -match "Creator Process Name:(.*)"} | ForEach-Object {$($matches.1).trim()}
		[PSCustomObject]@{
			SID = $securityID
			NewProcessName = $(Split-Path $NewProcessName -Leaf)
			CreatorProcessName = $(Split-Path $CreatorProcessName -Leaf)
		}
		} | Where-Object {$null -ne $_.CreatorProcessName} | Group-Object CreatorProcessName | ForEach-Object {
		$Accounts = $_.group.sid | Group-Object | ForEach-Object {$_.name}| convertto-json -Compress 
		[PSCustomObject]@{
			CreatorProcessName = $_.name
            NewProcessName = $($_.group.newprocessname | Group-Object | ForEach-Object {$_.name} | convertto-json -Compress)
			Account = $Accounts.replace("`"","").replace("\","")	
            Count = $_.count
			PartitionKey = $env:COMPUTERNAME
			RowKey = $_.name
			z_IntuneUPN = $hw['IntuneUPN']
			z_IntuneDate = $hw['IntuneDate']
			z_Model = $hw['Model']
		}
	}
	# Write-UpdateScreen "Get PrivUsage: $($PrivUsage.count)"
	$PrivUsage | ForEach-Object {
		Publish-AzITSTableRowPrivate -logentry $PSItem -table "EventsAdminToken" 
	} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload PrivUsage: $($_.Name); qty $($_.count)"}


	# EventsReportWER
	$WER = Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\WER\ReportArchive" -filter Report.wer -recurse | ForEach-Object {
		$b = Get-Content -Path $_.FullName | ForEach-Object {$_ -replace '\\', '\\'} | ConvertFrom-StringData 
		$datetime = [datetime]::FromFileTime($b.EventTime)
		$datetime = Get-Date $datetime -format s -ErrorAction SilentlyContinue
		[PSCustomObject]@{
			EventType = $b.EventType
			OriginalFilename = $b.OriginalFilename
			EventTime = $datetime
			PartitionKey = $env:COMPUTERNAME
			RowKey = $datetime
			z_IntuneUPN = $hw['IntuneUPN']
			z_IntuneDate = $hw['IntuneDate']
			z_Model = $hw['Model']
		}
	}
	$WER | ForEach-Object { Publish-AzITSTableRowPrivate -logentry $PSItem -table "EventsReportWER" } | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsReportWER: $($_.Name); qty $($_.count)"}
	
	$hw['PartitionKey'] = "$([System.Net.Dns]::GetHostName())"
	$hw['RowKey'] = $(Get-Date -format s)
	$hw['A_PrivUsage'] = $($PrivUsage.count)
	$hw['A_TaskResults'] = $($taskresults.count)
	$hw['A_Reboots'] = $($otherreboots.count) + $($shutdown.count)
	$hw['A_MSI'] = $($MSIInstallers.count)
	$hw['A_MDM'] = "$($mdmevents.count), $($mdmEventsExtended.count)"
	$hw['A_WLAN'] = $($wlanreport.count)
	$hw['A_WER'] = $($WER.count)
	$hw['A_Drivers'] = $($AllDrivers.count)
	$hw['A_Error'] = $($allerrors.count)
	$hw['A_BSOD'] = $($bsod.count)
	$hw['A_Teams'] = $($EventsTeams.count)	
	$hw['A_Zoom'] = $($eventszoom.count)
	$hw['A_ZoomCrashes'] = $($CrashesZoom.count)
	$hw['A_ZoomFiles'] = "Files: $($eventszoomfiles); MB: $eventszoomfilesMB"
	$hw["Z_Runtime"] = $([Math]::Round($runtime.elapsed.TotalMinutes,2))
	Publish-AzITSTableRowPrivate -logentry $hw -table EventsMain  | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Upload EventsMain: $($_.Name); qty $($_.count)"}
		
	Receive-PennLawITS
	invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneHWSW.ps1`" -noprofile"
	invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneWindowsUpdate.ps1`" -noprofile"
	invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneASRrules.ps1`" -noprofile"
	invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"C:\Penn Law ITS\Scripts\IntuneAppLocker.ps1`" -noprofile"
		
	Exit 0
}



catch {
	$_
	$hw['RowKey'] = Get-Date | ForEach-Object {$_.ticks}
	Publish-AzITSTableRowPrivate -logentry $hw -table EventsMain -catch $_ -isdiagnostics $transcript | Out-Null
	# Exit 8469
}
finally {
	Write-UpdateScreen "Finally Block: Runtime: $([Math]::Round($runtime.elapsed.TotalMinutes,2))" 
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU1V1rS4o3+yDT2jwBXbrdpxzS
# Ix2gggNOMIIDSjCCAjKgAwIBAgIQOkc97gsleplN8l0O0Ma6dDANBgkqhkiG9w0B
# AQsFADAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbTAe
# Fw0yMjEwMjUxNjExMjdaFw0zMjEwMjUxNjIxMjdaMCgxJjAkBgNVBAMMHXBlbm5s
# YXdzY2hvb2wub25taWNyb3NvZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAzEivfrSRdZt2GtCEhsRYLlyNUZNkJiJFgClY/gOjdKljfKwIGvQs
# eqogAzn09jEq8n84mrgOhHLH77M5ktvp1Agd/GUDccXTRITCcD+WEP6vu3ckji65
# u+yYmZfdPwAuIAQMTLLTEMd4LnPWYGkocBvZhwbxzmD3I8So4UFnlBXnJy2XNHlQ
# 4SqnD03Y9HbAq7c7dSvpocYbXfDme9IuppuEvuEf69b4MyNqR8pgSKBWnPiYwNrY
# LgrEOhmumwrB3A2Mh+7Q4Kfwp75PBXvqMzNlPa8C080Eue38PeOTHRjIR4BWU2Iv
# +4h3j/IUq/ZAvmWCNYUgpANn3R9w0ljjXQIDAQABo3AwbjAOBgNVHQ8BAf8EBAMC
# B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwKAYDVR0RBCEwH4IdcGVubmxhd3NjaG9v
# bC5vbm1pY3Jvc29mdC5jb20wHQYDVR0OBBYEFFAxmJnCGR+bbZLTmp1Q9AxVsNpq
# MA0GCSqGSIb3DQEBCwUAA4IBAQAP4Labzeq+V2RbjJkaB/iM1aFihLsgCwnIJCXI
# SsggD7/x8odE6SS0rR2UBUvsliql9jxj2jJSwaqD5SB9QNOqBMT3QbMHSRxJokic
# qHb5YBnmvyJuBUsPo2plQDVsMuBG3K1qwxRoBfFN7Xl0+CpuuriCAabztucxMuY/
# 0G0ThgA9Zq7nooBfK7Lfben5bIucOGsvpXKDgvAAlWcJooT3PavCUd+j63TxhwSx
# uZ8vVZeqd9Dj9qITZvLOP+KCSoQY2gPqEhoEaMxYwSqCng1zVB++mgZ4eMiNx4Wm
# D8aRQ3ewaaPXO+ePkqfUYXiAFWzKUWtUs11mmUXSaiq9/tN2MYIB3TCCAdkCAQEw
# PDAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbQIQOkc9
# 7gsleplN8l0O0Ma6dDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU+pHuXumqm7J3sBj3gZtqqXDX
# kpQwDQYJKoZIhvcNAQEBBQAEggEABCijLCSiaxHMS3uu5vfVjNZ7SaJT0PrKGSDF
# CGReSteYPuhRkv/+eKxBX20gDtj7bx6Gpy+vaETWmZXTmXAfz6d4EaZUvjCsNlG/
# MzerReiI2HlxdY4ycy3NdyRqXB56zKoeodpjrMH9MxVjOTD5sudwyX5dy+g+4kur
# lWoj9sBxu0RQeAuA/D793aEB5KLMUQdfUHqcI7ViIsxTjpx37YVTDo0RxjmjwYf9
# AhQqU65j8zcF3ltHAJWccxlg3pMeA2UbEcwVb+siqSsDtDIbFp7SDO5BeHk8n05P
# Xq6ttid3i1G49KJgFdPSOO0sYghf7jWetFA4d+I2MyTlMGKVqw==
# SIG # End signature block
