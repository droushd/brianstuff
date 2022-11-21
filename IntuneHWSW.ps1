[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:ErrorActionPreference = "SilentlyContinue"
Function Write-UpdateScreen ($message) {Write-Output "[$(Get-Date -format "H:mm:ss")] $message"}
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
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$iserror,
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
      if (-not($AzITSTableRow)) {$AzITSTableRow = 0}
      $AzITSTableRow += 1
      if ($AzITSTableRow -eq 1 -And $isfinally) {return}

      # $zLogEntry = $logentry | convertto-json -Depth 9
      if ($iserror) {
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

      try {
          Invoke-WebRequest -Method PUT -Uri $URI -Headers $RequestHeaders -Body $EncodedRequestBody -ContentType "application/json" -UseBasicParsing #| foreach {($_.StatusCode)}
      }
      
      catch [System.Net.WebException] { 
        Write-Verbose "An exception was caught: $($_.Exception.Message)"
        $_.Exception.Response
      }
  }        
} # End Function Publish-AzITSTableRowPrivate
try {
	$private:ScriptName = "IntuneHWSW.ps1" 
    $private:itsallTable = "Inventory"
	$private:transcript = $("$env:temp\$ScriptName" + $(Get-Date | ForEach-Object {$_.ticks}) + ".txt") -replace ".ps1","_" 
    Start-Transcript -Path $transcript  -IncludeInvocationHeader | ForEach-Object {Write-UpdateScreen $_}
	$ErrorActionPreference = "SilentlyContinue"
	$private:perfchecks = New-Object System.Collections.ArrayList($null)  #New-Object PSCustomObject
	$private:runtime =  [system.diagnostics.stopwatch]::StartNew()
    
    if ($PSCommandPath -match 'droush') {
        Write-UpdateScreen "Publishing updated version of script first"
        try{Publish-AzITSAll .\$ScriptName}
		catch {$_}
    }

    $checkPSUpdates = Get-ChildItem -Path "C:\Windows\Temp" -Filter "IntunePSUpdates*.txt"
	$Win10ITSexists_current =  Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\Win10ITS" | Sort-Object LastWriteTime -Descending | Select-Object -first 1 | ForEach-Object {$_.name}
	$win10itsExists = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue
	$win10itsImported = "C:\Program Files\WindowsPowerShell\Modules\Win10ITS\$Win10ITSexists_current\win10its.psd1"
	if ($Win10ITSexists_current) {
        if (-not$win10itsExists) {
			Write-UpdateScreen "ERROR: Win10ITS exists but isn't importing"
			Import-Module $win10itsImported
			$win10itsExists = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue | ForEach-Object {$_.version}
			Write-UpdateScreen "ERROR: Win10ITS manually importing ($Win10ITSexists_current)"
            try {$private:hw = Get-Inven}
            catch {$private:hw = New-Object 'system.collections.generic.dictionary[string,string]'}
            $hw['Win10ITS'] = "$Win10ITSexists_current;$false"
		}
        else {
            Write-UpdateScreen "using Get-Inven"
            try {$private:hw = Get-Inven }
            catch {$private:hw = New-Object 'system.collections.generic.dictionary[string,string]'}
            $hw['Win10ITS'] = "$Win10ITSexists_current;$true"
        }
		Receive-PennLawITS
    }
    elseif ($null -eq $checkPSUpdates) {
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
		# invoke-expression "cmd /c start powershell -windowstyle hidden -ex bypass -file `"$PSCommandPath`" -noprofile";
		Start-Process -File cmd -ArgumentList "/c start powershell -noexit -noprofile -ex bypass -file `"$PSCommandPath`""
		Exit $($hw["$($ordered)ExitCode"])
    }
	
	if ($null -ne $PSCommandpath) {
		Clear-Variable -name matches -ErrorAction SilentlyContinue
		$PSCommandpath -match "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}" | Out-Null
		if ($null -ne $matches) {$hw['z_PSCommandPath'] = $matches[0]}
		else {$hw['z_PSCommandPath'] = $PSCommandPath}
	}
		
	$hw['z_PSGet'] = Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\" | Sort-Object name -descending | Select-Object -First 1 | ForEach-Object {$_.name}
	$hw['z_Schedtasks'] = Get-ScheduledTask | Where-Object {$_.TaskName -match 'pennlaw'} | ForEach-Object {$_.TaskName} | convertto-json -compress

	$hw['PartitionKey'] = "$([System.Net.Dns]::GetHostName())"
	if ($($hw['Monitors']) -notmatch "Dell") {$hw['RowKey'] = "$($hw['IntuneUPN'])_undocked"}
	else {$hw['RowKey'] = "$($hw['IntuneUPN'])"}

	$BDEqty = manage-bde -status | ForEach-Object {$_.split("`n")} | Where-Object { $_ -match 'reboots left'} | ForEach-Object {$_.replace(' reboots left)','').split("(")}| Select-Object -last 1
	$hw['Bitlocker'] = Get-BitLockerVolume C: | ForEach-Object {"$($_.protectionstatus):$($_.VolumeStatus)"} | Out-String
    $hw['Bitlocker'] = "$($hw['Bitlocker']);$BDEqty"  
	
    $hw['TimeZoneSync'] = Invoke-Command {
        Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type"  | ForEach-Object {$_ -match "NTP"}
        Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name "Start"  | ForEach-Object {$_ -match 3}
    } | Group-Object | ForEach-Object {$_.name}    
    $hw['TimeZone'] = $(Get-TimeZone | ForEach-Object {$_.id})
    $hw['TimeService'] = Get-Service w32time | ForEach-Object {"$($_.Status): $($_.starttype)"}


	$recoverypartitions = Get-CIMInstance -Class win32_volume | Where-Object {$_.label -match "dellsupport"} | ForEach-Object {$true}
	$hw['DellRecovery'] = $recoverypartitions

	$cctkEXE = "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe" # https://www.dell.com/support/kbdoc/en-us/000147084/dell-command-configure-error-codes
	if ($($hw['Manufacturer']) -match "dell") {
		if (!(Test-Path $cctkEXE)) {Receive-ITSDownload -FileName Dell-Command-Configure_KVF2C_WIN_4.6.0.277_A00_01.EXE | ForEach-Object {Start-Process -FilePath $_.path -ArgumentList "/s" -Wait}}

		# $uri = Invoke-WebRequest -Uri https://www.dell.com/support/kbdoc/en-us/000178000/dell-command-configure | foreach {$_.links} | where {$_ -match 'Windows download' } | select -first 1 | foreach {$_.href}

		if (Test-Path $cctkEXE) {
			Write-UpdateScreen "Dell CCTK Settings"
			
			$outfile = "$env:temp\cctk.txt"
			&$cctkEXE --outfile $outfile
			$cctkINFO = New-Object 'system.collections.generic.dictionary[string,string]'
			if ($PSVersionTable.PSEdition -notmatch "Core") {
				Get-Content $outfile | ForEach-Object {$_ -replace ";",""} | Where-Object {$_ -match '=' -And $_ -notmatch 'Here '}| ConvertFrom-StringData | ForEach-Object {
					$cctkINFO["$($_.keys)"] = $_.values
				}	
			}
			else {
				Get-Content $outfile | ForEach-Object {$_ -replace ";",""} | Where-Object {$_ -match '=' -And $_ -notmatch 'Here '}| ConvertFrom-StringData -Delimiter "="  | ForEach-Object {
					$cctkINFO["$($_.keys)"] = $_.values
				}	
			}
			$cctkINFO['PartitionKey'] = $env:computername 
			$cctkINFO['RowKey'] = $hw['IntuneUPN'] 
			$cctkINFO['A_Model'] = $hw['Model'] 
			
			Publish-AzITSTableRow -logentry $cctkINFO -table SettingsDellBIOS | ForEach-Object {"Uploading Dell BIOS Settings: $($_.StatusCode)"}		
			
			try {
		
				$hw['DellDateMfg'] = $cctkINFO['MfgDate'] | ForEach-Object {[datetime]::parseexact($($PSItem), 'yyyymdd',$null)} | ForEach-Object {Get-Date $PSItem -format "yyyy-m-dd"}
				$hw['DellDateFirst'] = $cctkINFO['FirstPowerOnDate'] | ForEach-Object {[datetime]::parseexact($($PSItem), 'yyyymdd',$null)} | ForEach-Object {Get-Date $PSItem -format "yyyy-m-dd"}			
				$hw['DellBIOSConnect'] = $cctkINFO['BIOSConnect']
				if ($null -ne  $($hw['DellDateMfg'])) {
					try {
						$hw['DellDateAge'] = New-TimeSpan -Start $(Get-Date $($hw['DellDateMfg'])) -End (Get-Date) | ForEach-Object {[Math]::Round($($_.TotalDays)/365,2)} 
					}
					catch {
						Write-UpdateScreen "unable to get dellDateAge timespan"
					}			
				}
	
			}
			catch {Write-UpdateScreen "unable to get dell CCTK info"}			
		}
	}

	$computerinfo = @{}	
	(Get-ComputerInfo).PSObject.Properties | Select-Object name, value | 
	# where {$_.name -notmatch "^CIM"} |
	# Where-Object {$_.name -notmatch "^CIM|SignatureFallbackOrder|ControlledFolderAccessAllowed|ExclusionProcess|AttackSurfaceReductionRules|AttackSurfaceReductionOnly|ExclusionPath"} | 
	Where-Object {$null -ne $_.value -And $_.value.gettype() -notmatch 'Timespan'} |
	# where {$_.name.length -lt 25} |
	ForEach-Object {
		if ($_.value.gettype().basetype -match "Array|Object") {
			$value = $_.value | convertto-json -compress
		}
		else {$value = $_.value}
		# https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity
		if ($_.name -match "DeviceGuardSecurityServicesRunning") {
			$securityservicesRunning = @{
				0 = "None"
				1 = "CredentialGuard"
				2 = "HypervisorEnforcedCodeIntegrity"
				3 = "Secure Launch"
				4 = "SMM Firmware Measurement"
			}
			$securityservicesRunning.getenumerator() | foreach {
				$value = $value -replace $_.name,$_.value
			}
		}
		$computerinfo["$($_.name)"] = $value
		# https://go.microsoft.com/fwlink/?LinkId=2162953
	}
	$computerinfo['RowKey'] = $hw['IntuneUPN']
	$computerinfo['PartitionKey'] = $env:computername
	try{Publish-AzITSTableRow -logentry $computerinfo -table SettingsComputerInfo | Out-Null}
	catch {Write-UpdateScreen "Error: ComputerInfo: $($_.StatusCode)"} #


	$MpPreference = @{}
	$mpcomputerstatus = @{}
	# Get-MpPreference | foreach {$_.PSObject.Properties} | foreach {
	# 	$value = $($_.Value | COnvertto-json -compress)
	# 	if ($value.length -gt 50) {
	# 		$value = $value.substring(1,50)
	# 	}
	# 	if ($_.name.length -gt 25){
	# 		$name = $($_.name).substring(1,25)
	# 	}
	# 	else {$name = $_.name}
	# 	$MpPreference["$name"] = $value
	# }
	(Get-MpComputerStatus).PSObject.Properties | Select-Object name, value | Where-Object {$_.name -notmatch "^CIM"} | ForEach-Object {$mpcomputerstatus["$($_.name)"] = $($_.value)}
	(Get-MpPreference).PSObject.Properties | Select-Object name, value | 
		# where {$_.name -notmatch "^CIM"} |
		Where-Object {$_.name -notmatch "^CIM|SignatureFallbackOrder|ControlledFolderAccessAllowed|ExclusionProcess|AttackSurfaceReductionRules|AttackSurfaceReductionOnly|ExclusionPath"} | 
		Where-Object {$null -ne $_.value -And $_.value.gettype() -notmatch 'Timespan'} |
		# where {$_.name.length -lt 25} |
		ForEach-Object {$MpPreference["$($_.name)"] = $($_.value)}

	$MpPreference['RowKey'] = $hw['IntuneUPN']
	$MpPreference['PartitionKey'] = $env:computername
	try{Publish-AzITSTableRow -logentry $MpPreference -table SettingsMPPreference | Out-Null}
	catch {Write-UpdateScreen "Error: MPPreference: $($_.StatusCode)"} #
	
	# get-mpcomputerstatus | foreach {$_.PSObject.Properties} |  foreach {$mpcomputerstatus["$($_.Name)"] = $($_.Value | COnvertto-json -compress)}
	$mpcomputerstatus['RowKey'] = $hw['IntuneUPN']
	$mpcomputerstatus['PartitionKey'] = $env:computername
	
	try{Publish-AzITSTableRow -logentry $mpcomputerstatus -table SettingsMPComputerStatus | Out-Null}
	catch {Write-UpdateScreen "Error: MPStatus: $($_.StatusCode)"} #| Out-Null

	$hw['IPSec'] = Get-NetIPsecRule | Group-Object InboundSecurity, OutboundSecurity | ForEach-Object {"Rule: $($_.Name); Qty $($_.Count); Names: $(Get-NetIPsecRule | ForEach-Object {$_.displayname} | convertto-json -Compress)"} 
    Write-UpdateScreen "Get ITSBackup"
	# $hw['ITSBackup'] = Sync-OneDriveToHDD -ErrorAction SilentlyContinue | ForEach-Object {Get-FolderSizes $PSItem} | convertto-json -compress
	$hw['ITSBackup'] = Get-ChildItem -erroraction silentlycontinue "C:\Users\$($hw['IntuneUPN'])\OneDrive - University of Pennsylvania Law School\ITSBackup\" | Sort-Object LastWriteTime -Descending | Select-Object -first 2 | ForEach-Object {
		[PSCustomObject]@{
			Name = $_.FullName.Replace("C:\Users\$($hw['IntuneUPN'])\OneDrive - University of Pennsylvania Law School\ITSBackup\","")
			Date = $(Get-Date $_.LastWriteTime -format s)
		}
		} | Convertto-json -Compress
	try {$intuneAge = (Get-Date) - (get-date $hw['IntuneDate']) | ForEach-Object {$_.totaldays}}
	catch {$intuneAge = $false}
	$newcomputerPath = "C:\Penn Law ITS\Scripts\IntuneNewComputer.txt"
	if (-not(Test-Path $newcomputerPath) -And $intuneAge -gt 30) {
		Write-UpdateScreen "Mimic IntuneNewComputer.txt if missing"
		Copy-Item $transcript $newcomputerPath -Force
	}
	$hw['SMBShares'] = Get-SmbShare | Where-Object {$_.sharestate -eq 'online'} | ForEach-Object {$_.name} | convertto-json -Compress
	$hw['SMBOffline'] = Get-SmbShare | Where-Object {$_.CachingMode -ne 'manual'} | ForEach-Object {"Name: $($_.Name); CachingMode: $($_.CachingMode)"} | convertto-json -compress
	#Get-Hkey -Path "HKLM:\Software\Policies\Microsoft\Windows\NetCache" -Name "Enabled" | where {$_ -eq 1}
	$hw['SMBEveryone'] = Get-SmbShare | Get-SmbShareAccess | Where-Object {$_.AccountName -match 'everyone'} | ForEach-Object {"Name: $($_.Name); ACL: $($_.AccessRight)"} | convertto-json -compress

	$RDP = Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" | ForEach-Object {$_ -eq 1}
	$TLS = Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" | ForEach-Object {$_ -eq 2}
	$Enc = Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" | ForEach-Object {$_}
	$hw['RDP'] = "Off: $RDP; TLS: $TLS; Enc: $Enc"

	$clsid_full = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\UnitedVideo\CONTROL\VIDEO -ErrorAction SilentlyContinue | ForEach-Object {$_.name}
	if ($clsid_full) {
		$clsid = Split-Path $clsid_full -Leaf
		$path = "HKLM:\SYSTEM\CurrentControlSet\Control\UnitedVideo\CONTROL\VIDEO\$clsid"
		$subkeys = Get-HKEY -Path $path -subkeys
		$output = $subkeys | ForEach-Object {
			$path = "HKLM:\SYSTEM\CurrentControlSet\Control\UnitedVideo\CONTROL\VIDEO\$clsid\$PSItem"
			[PSCustomObject]@{
				x = $(Get-HKEY -Path $path -Name DefaultSettings.xResolution)
				y = $(Get-HKEY -Path $path -Name DefaultSettings.yResolution)
			}
		} | Where-Object {$null -ne $_.x} | ForEach-Object {"$($_.x)x$($_.y)"}
		$hw['MonitorsXY'] = $output -join "; "
	}
	$hw['MonitorsScaling'] = Invoke-Command {
		$logpixels = Get-HKEY -Path "HKCU:\Control Panel\Desktop" -Name LogPixels | Group-Object | ForEach-Object {$_.name}
		if ($logpixels.length -lt 1) {'notSet'}
		$Win8DpiScaling = Get-HKEY -Path "HKCU:\Control Panel\Desktop" -Name Win8DpiScaling | Group-Object | ForEach-Object {$_.name -match '0'}
		"$logpixels; $Win8DpiScaling"
	}

	# $hw['USB'] = get-wmiobject -class Win32_USBControllerDevice -ErrorAction SilentlyContinue | ForEach-Object {[wmi]($PSItem.Dependent)} | 
	# 	Where-Object {$_.name -notmatch 'Wireless Bluetooth|Integrated Webcam|Generic USB Hub|USB Root Hub|USB Composite Device|USB Input Device|HID'} | ForEach-Object {$_.name} | convertto-json
	# $hw['Scanner'] = Get-WmiObject -class Win32_USBControllerDevice -ErrorAction SilentlyContinue |  
	# 	ForEach-Object {($PSItem.Dependent)} | Where-Object {$PSItem.manufacturer -match "Epson|Fuji"} | 
	# 	ForEach-Object {$PSItem.name + "," + $PSItem.deviceid.split("\")[2]}
		# Get-CimInstance -namespace root\CIMV2 -Query "Select * from Win32_USBControllerDevice" |  Group-Object name | ForEach-Object {$_.name} | convertto-json -compress

	$hw['WebCam'] = Get-CimInstance -namespace root\CIMV2 -Query "Select * from Win32_PnPEntity where PNPClass LIKE 'Camera'" |  Group-Object name | ForEach-Object {$_.name} | convertto-json -compress

	if ($($hw['Model']) -notmatch "Optiplex" -And $PSVersionTable.PSEdition -notmatch "Core") {
		Write-UpdateScreen "battery health"
		$fullchargecapacity = Get-CimInstance -namespace root\WMI -Query "Select * from BatteryFullChargedCapacity" | ForEach-Object {$_.FullChargedCapacity}
		$designcapacity = Get-WmiObject -namespace root\WMI  -Query "Select * from BatteryStaticData" | ForEach-Object {$_.DesignedCapacity} 
		# if (-not($fullchargecapacity ) -Or -not($designcapacity)) {$batteryhealth = 0} 
		# elseif (($fullchargecapacity / $designcapacity) -gt 1) {$batteryhealth = 100} 
		try { $hw['BatteryRx'] = [decimal]::round(($fullchargecapacity / $designcapacity) * 100) }
		catch { $hw['BatteryRx'] = "err"}
	}  
	$hw['WRSS'] = Invoke-Command { 
		try {
		import-module dism
		Get-WindowsReservedStorageState | out-string | convertfrom-string -Delimiter ":" | ForEach-Object {$_.p2.trim()}
		}
		catch {"err"}
	}

	Write-UpdateScreen "Collecting: UserRights: $($_.StatusCode)"
    $priv = @"
	[
		{"Priv":"SeNetworkLogonRight ","Value":" *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"},
		{"Priv":"SeBackupPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeChangeNotifyPrivilege ","Value":" *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"},
		{"Priv":"SeSystemtimePrivilege ","Value":" *S-1-5-19,*S-1-5-32-544"},
		{"Priv":"SeCreatePagefilePrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeDebugPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeAuditPrivilege ","Value":" *S-1-5-19,*S-1-5-20"},
		{"Priv":"SeIncreaseQuotaPrivilege ","Value":" *S-1-5-19,*S-1-5-20,*S-1-5-32-544"},
		{"Priv":"SeIncreaseBasePriorityPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeLoadDriverPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeBatchLogonRight ","Value":" *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559"},
		{"Priv":"SeServiceLogonRight ","Value":" *S-1-5-80-0"},
		{"Priv":"SeInteractiveLogonRight ","Value":" Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"},
		{"Priv":"SeSecurityPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeSystemEnvironmentPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeProfileSingleProcessPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeSystemProfilePrivilege ","Value":" *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"},
		{"Priv":"SeAssignPrimaryTokenPrivilege ","Value":" *S-1-5-19,*S-1-5-20"},
		{"Priv":"SeRestorePrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeShutdownPrivilege ","Value":" *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"},
		{"Priv":"SeTakeOwnershipPrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeDenyNetworkLogonRight ","Value":" *S-1-5-32-555"},
		{"Priv":"SeUndockPrivilege ","Value":" *S-1-5-32-544,*S-1-5-32-545"},
		{"Priv":"SeManageVolumePrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeRemoteInteractiveLogonRight ","Value":" *S-1-5-32-544,*S-1-5-32-555"},
		{"Priv":"SeDenyRemoteInteractiveLogonRight ","Value":" *S-1-5-32-544,*S-1-5-32-555"},
		{"Priv":"SeImpersonatePrivilege ","Value":" *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"},
		{"Priv":"SeCreateGlobalPrivilege ","Value":" *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"},
		{"Priv":"SeIncreaseWorkingSetPrivilege ","Value":" *S-1-5-32-545"},
		{"Priv":"SeTimeZonePrivilege ","Value":" *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545"},
		{"Priv":"SeDelegateSessionUserImpersonatePrivilege ","Value":" *S-1-5-32-544"},
		{"Priv":"SeCreatePermanentPrivilege","Value":""},{"Priv":"SeCreateSymbolicLinkPrivilege","Value":""},
		{"Priv":"SeCreateTokenPrivilege","Value":""},{"Priv":"SeDenyBatchLogonRight","Value":""},
		{"Priv":"SeDenyInteractiveLogonRight","Value":""},
		{"Priv":"SeDenyServiceLogonRight","Value":""},
		{"Priv":"SeEnableDelegationPrivilege","Value":""},
		{"Priv":"SeLockMemoryPrivilege","Value":""},
		{"Priv":"SeMachineAccountPrivilege","Value":""},
		{"Priv":"SeRelabelPrivilege","Value":""},
		{"Priv":"SeRemoteShutdownPrivilege","Value":""},
		{"Priv":"SeSyncAgentPrivilege","Value":""},
		{"Priv":"SeTcbPrivilege","Value":""},
		{"Priv":"SeTrustedCredManAccessPrivilege","Value":""}
	]
"@   | foreach {COnvertfrom-json $_}
    $privs = $priv.priv.trim() -join "|"
	
	$SIDs = @"
	[
		{"name":"group_adminaccounts_deviceadmins","SID":"S-1-12-1-452868666-1143483705-728492724-1260444873"},		
		{"name":"AADDeviceLocalAdmin","SID":"S-1-12-1-2574265528-1097632912-3783964841-3249981438"},		
		{"name":"DEM-Classroom","SID":"S-1-12-1-2652883840-1129994154-863781561-2060981278"},		
		{"name":"AP-Classroom","SID":"S-1-12-1-2031579122-1236419968-398143415-3697414700"},	
		{"name":"GlobalAdmin","SID":"S-1-12-1-3700390433-1132171205-3554173330-2107943479"},	
		{"name":"group_adminaccounts_cloudadmins","SID":"S-1-12-1-3868315169-1189551379-2204501136-2236855532"},
		{"name":"Virtual Machines","SID":"S-1-5-83-0"},
		{"name":"Everyone","SID":"S-1-1-0"},
		{"name":"NETWORK SERVICE","SID":"S-1-5-20"},
		{"name":"Administrators","SID":"S-1-5-32-544"},
		{"name":"Performance Log Users","SID":"S-1-5-32-559"},
		{"name":"Backup Operators","SID":"S-1-5-32-551"},
		{"name":"SERVICE","SID":"S-1-5-6"},
		{"name":"Remote Desktop Users","SID":"S-1-5-32-555"},
		{"name":"Users","SID":"S-1-5-32-545"},
		{"name":"ALL SERVICES","SID":"S-1-5-80-0"},
		{"name":"WdiServiceHost","SID":"S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"},
		{"name":"LOCAL SERVICE","SID":"S-1-5-19"},
		{"name":"Guest","SID":"S-1-5-32-546"},
		{"name":"IUSR","SID":"S-1-5-17"}, 
		{"name":"Authenticated Users","SID":"S-1-5-11"}, 
		{"name":"Interactive","SID":"S-1-5-4"}
	]
"@   | foreach {COnvertfrom-json $_}
	$domains = @("Net\\","BUILTIN","NT AUTHORITY","Window Manager","NT VIRTUAL MACHINE","NT SERVICE",$env:computername)
	$logentry = @{}
	$logentry['PartitionKey'] = $([System.Net.Dns]::GetHostName())
    $logentry['RowKey'] =  $hw['IntuneUPN']
	$accesschk = 'C:\Penn Law ITS\Diagnostics\accesschk.exe'
	$accesschk_exists = Test-Path $accesschk
    if (-not$accesschk_exists) {
		$Destination = Receive-ITSDownload -FileName AccessChk.zip | foreach {$_.path}
    	Expand-Archive -Path $Destination -DestinationPath 'C:\Penn Law ITS\Diagnostics' -Force
	}
    $priv.priv.trim() | foreach {
        $item = &$accesschk -accepteula -nobanner -a $_ 
        if ($item -match "No Accounts") {$item = $null}
        if ($null -ne $item) {
            $SIDs | foreach {
				$item = $item -replace $_.SID,$_.name 
            }
			$domains | foreach {
				$item = $item -replace $_,""
            }
			$item = $item -replace "\\",""
            $item = $($item -split "," | sort) -join ", "
			$name = $_.trim()
            $logentry[$name] = $item         
        }
        else {
            $logentry[$_] = $null
        }
    }
	try{Publish-AzITSTableRow -logentry $logentry -table SettingsUserRights | Out-Null}
	catch {Write-UpdateScreen "Error: UserRights: $($_.StatusCode)"} #
    
	Write-UpdateScreen "Collection Local Groups"
	try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctype = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ctype, $env:COMPUTERNAME
        $idtype = [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName
        
    }
    catch {Write-ITSHost "failed netgroup :("}
	$logentry = @{}
	$logentry['PartitionKey'] = $([System.Net.Dns]::GetHostName())
    $logentry['RowKey'] =  $hw['IntuneUPN']

	Get-LocalGroup | foreach {
		$NETgroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context, $idtype, $_.name)
		$item = $netgroup.members.sid.value
		if ($item.length -gt 3) {
			$SIDs | foreach {
				$item = $item -replace $_.SID,$_.name 
			}
			$domains | foreach {
				$item = $item -replace $_,""
			}
			$NETgroup.members | foreach {
				$item = $item -replace $_.SID,$_.samaccountname 
			}
			$item = $item -replace "\\",""
			$item = $($item -split "," | sort) -join ", "
			$Name = $_.name.trim() -replace " ","_"
			$logentry[$name] = $item	
		}
	}
	try{Publish-AzITSTableRow -logentry $logentry -table SettingsLocalGroups | Out-Null}
	catch {Write-UpdateScreen "Error: LocalGroups: $($_.StatusCode)"} #


	Write-UpdateScreen "get printers" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
	# start converting constants from this page: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-printer
	# $hw = get-inven
	$ezOrdered = "A_"
	$detectedErrorState = @{
		7 = "Door Open"
		8 = "Jammed"
		3 = "Low Paper"
		5 = "Low Toner"
		2 = "No Error"
		4 = "No Paper"
		6 = "No Toner"
		9 = "Offline"
		1 = "Other"
		11 = "Output Bin Full"
		10 = "Service Requested"
		0 = "Unknown"
	}
	$ExtendedPrinterStatus = @{
		1 = "Other"
		2 = "Unknown"
		3 = "Idle"
		4 = "Printing"
		5 = "Warming Up"
		6 = "Stopped Printing"
		7 = "Offline"
		8 = "Paused"
		9 = "Error"
		10 = "Busy"
		11 = "Not Available"
		12 = "Waiting"
		13 = "Processing"
		14 = "Initialization"
		15 = "Power Save"
		16 = "Pending Deletion"
		17 = "I/O Active"
		18 = "Manual Feed"
	}
	$PrinterStatus = @{
		3 = "Idle"
		7 = "Offline"
		1 = "Other"
		4 = "Printing"
		6 = "Stopped Printing"
		2 = "Unknown"
		5 = "Warmup"
	}
	$ExtendedDetectedErrorState = @{
		0 = "Unknown"
		1 = "Other"
		10 = "Output Bin Full"
		11 = "Paper Problem"
		12 = "Cannot Print Page"
		13 = "User Intervention Required"
		14 = "Out of Memory"
		15 = "Server Unknown"
		2 = "No Error"
		3 = "Low Paper"
		4 = "No Paper"
		5 = "Low Toner"
		6 = "No Toner"
		7 = "Door Open"
		8 = "Jammed"
		9 = "Service Requested"
	}
	Get-CimInstance -ClassName win32_printer | Where-Object {$_.Name -notmatch "OneNote|XPS|PDF|Fax|Snagit"} | ForEach-Object {
		$Printers = @{}
		$item = $_.PSObject.Properties
		$item | Where-Object {$_.name -notmatch "^CIM" -And $null -ne $_.value -And $_.value.gettype() -notmatch 'Timespan'} | ForEach-Object {
			$typeinfo = $_.value.gettype()
			$name = $_.name
			if ($typeinfo.BaseType.Name -match "Array") {
				$value = $_.value -join ", "
			}
			elseif ($_.name -match "^DetectedErrorState") {
				$value = $detectedErrorState[$([int]$_.Value)]
				$name = "B_$($_.name)"
			}
			elseif ($_.name -match "^ExtendedPrinterStatus") {
				$value = $ExtendedPrinterStatus[$([int]$_.Value)]
				$name = "B_$($_.name)"
			}
			elseif ($_.name -match "^PrinterStatus") {
				$value = $PrinterStatus[$([int]$_.Value)]
				$name = "B_$($_.name)"
			}
			elseif ($_.name -match "^ExtendedDetectedErrorState") {
				$value = $ExtendedDetectedErrorState[$([int]$_.Value)]
				$name = "B_$($_.name)"
			}
			else {$value = $_.value}
			$Printers[$name] = $value
		}
		$hw.getenumerator() | Where-Object {$_.key -match 'IntuneUPN|Model|^OS$|OSBuild'} | ForEach-Object {
			$Printers["$($ezOrdered)$($_.key)"] = $_.value
		}
		$Printers['RowKey'] = $Printers["Name"] -replace "\\","."
		$Printers['PartitionKey'] = $env:computername
		if ($Printers['DriverName'] -match "Universal Print Class Driver") {
			$Printers["$($ezOrdered)Type"] = "Universal"
		}
		elseif ($Printers['ServerName'] -match "Kite") {
			$Printers["$($ezOrdered)Type"] = "Kite"
		}
		elseif ($Printers['PortName'] -match "WSD") {
			$Printers["$($ezOrdered)Type"] = "WSD"
		}
		else {
			$Printers["$($ezOrdered)Type"] = $Printers['PortName']
		}
		try{Publish-AzITSTableRow -logentry $Printers -table SettingsPrinters | Out-Null}
		catch {Write-UpdateScreen "Error: Printers: $($_.StatusCode)"} #
	} 

	$hw['Printers']  = Get-HKEY "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers" -subkeys | Where-Object {$_ -notmatch "OneNote|XPS|PDF|Fax|Snagit"} | COnvertto-json -Compress
	# 	if ($_ -match 'printers.law' -Or $_.PortName -match '130.91') {
	# 		$hw['PRNNet'] +="$($_.name -split "\\" | Select-Object -last 1);"
	# 	}
	# 	else {
	# 		$hw['PRNLocal'] += "$($_.name);"
	# 	}
	# }
	
	$hw['DiagTrack'] = Get-Service | Where-Object {$_.servicename -match 'diagtrack'} | ForEach-Object {$_.status}

	try {
		Write-ITSHost "Get Power Settings"
		$scheme = powercfg  /GETACTIVESCHEME
		$scheme = $scheme -split " " | ForEach-Object {
			$guid = $null
			try {$guid = [guid]::Parse($_) | ForEach-Object {$_.guid}}
			catch{}
			$guid
		}
		$SleepOriginal = powercfg -query $scheme  238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da | Where-Object {$_ -match 'Current AC Power Setting Index'} | ForEach-Object {$_ -split ":"} | Select-Object -last 1 | ForEach-Object {[uint32]$_.trim()}
		$SleepHibernateOriginal = powercfg -query $scheme  238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 | Where-Object {$_ -match 'Current AC Power Setting Index'} | ForEach-Object {$_ -split ":"} | Select-Object -last 1 | ForEach-Object {[uint32]$_.trim()}
		$hw['PowerSettingsAC'] = "Sleep: $($SleepOriginal); Hibernate: $SleepHibernateOriginal"
	}
	catch {
		$hw['PowerSettingsAC'] = "Sleep: $($SleepOriginal); Hibernate: $($SleepHibernateOriginal); err"
	}
	$AudioDeviceCmdlets_exists = test-path "C:\Program Files\WindowsPowerShell\Modules\AudioDeviceCmdlets"
 	if ($AudioDeviceCmdlets_exists -eq $false) {
		Install-Module -Name "AudioDeviceCmdlets" -Force -Scope AllUsers -SkipPublisherCheck
		Import-Module -Name "AudioDeviceCmdlets" -Force | Out-Null
    }
	$AudioDeviceCmdlets_exists = test-path "C:\Program Files\WindowsPowerShell\Modules\AudioDeviceCmdlets"
 	if ($AudioDeviceCmdlets_exists) {
		try {
			if ($PSVersionTable.PSVersion -notmatch "^5") {
				start-process -filepath powershell.exe -argumentlist '-WindowStyle Hidden -NonInteractive -Command {Invoke-Command -ScriptBlock {
					$audiodevices = Get-AudioDevice -List | Where-Object {$_.default -match $true}
					$audiodevices | convertto-json | out-file "C:\Windows\Temp\audiodevices.json"
				}}' -wait
				$audiodevices = Get-Content C:\Windows\Temp\audiodevices.json | convertfrom-json
			}
			else {
				$audiodevices = Get-AudioDevice -List | Where-Object {$_.default -match $true}
			}
			
			$hw['AudioRec'] =  $audiodevices | Where-Object {$_.type -match 'Recording'} | ForEach-Object {$_.name}
			$hw['AudioPlay'] = $audiodevices | Where-Object {$_.type -match 'Playback'} | ForEach-Object {$_.name}
		}
		catch{$_}
	}

	# CL setting: Dont set it here; use Intune
	# [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')  ## THIS IS CL, 0 is FullLanguage
	if ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage") {$hw['CLMode'] = $False}
	if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {$hw['CLMode'] = $True}
	$hw['z_EP'] = Get-ExecutionPolicy -List | Where-Object {$_.scope -match "LocalMachine"} | ForEach-Object {$_.executionpolicy}

	Write-UpdateScreen "Getting Software Inventory" | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
	$sw = Get-SW
	$sw_displayname_hash = @{}
	$sw | Where-Object {$null -ne $_.displayname} | & {process {$sw_displayname_hash[$($PSItem.displayname)] = $($PSItem) } }

	$hw['Adobe'] = $sw | Where-Object {$_.publisher -match 'adobe'} | Group-Object displayname | ForEach-Object {$_.name} | Where-Object {$_.length -gt 1 -And $_ -notmatch "Adobe Genuine Service|Adobe Refresh Manager"} | convertto-json -compress 
	# $hw['AdobeActivated'] = Get-HKEY -Path "HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name bIsSubscriptionUser | ForEach-Object {$_ -match '1'}
	
	$hw['dotNet'] = Get-ChildItem "c:\program files\dotnet\shared\Microsoft.NETCore.App" | ForEach-Object {$_.name} | convertto-json -compress

	$chrome_updatepolicy = Invoke-Command {
		Get-HKEY -Path "HKLM:\Software\Policies\Google\Chrome\" -Name RelaunchNotification | ForEach-Object {$_ -match 2}
		Get-HKEY -Path "HKLM:\Software\Policies\Google\Chrome\" -Name RelaunchNotificationPeriod  | ForEach-Object {$_ -match 172800000} 
	} | Group-Object | ForEach-Object {$_.name}

	$hw['CrashPlan'] = get-sw | Where-Object {$_.installlocation -match "code42|crashplan"} | ForEach-Object {$_.displayversion}
	
	$aaccounts = @('actolson','amayers-a','adroush','atjudice','adroush-endpoint','nswisher-a','acalrutz','addarrow','amjpierre')
	$demaccounts = @('its-deviceenroll','ap-classroom','dem-classroom','dem-clinlab','dem-itsclient','dem-lab')
	
	$hw['EdgeSync'] = Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Preferences"  | ForEach-Object {
		$Preferences_file = Get-Content $_.FullName | convertfrom-json
		if ($Preferences_file.account_info.email -match 'law.upenn.edu') {$Preferences_file.account_info.email}
		elseif ($Preferences_file.account_info.email.length -lt 1) {'notsyncing'}
		else {"other"}	
	}  | ForEach-Object {
		if ($_ -in $aaccounts) {"AAccount: $_"}
		elseif ($_ -in $demaccounts) {"DemAccount: $_"}
		else {$_}
	}  | convertto-json -Compress
	$hw['ChromeSync'] = Get-ChildItem "C:\Users\droush\AppData\Local\Google\Chrome\User Data\*\Preferences"  | ForEach-Object {
		$Preferences_file = Get-Content $_.FullName | convertfrom-json
		if ($Preferences_file.account_info.email -match 'law.upenn.edu') {$Preferences_file.account_info.email}
		elseif ($Preferences_file.account_info.email.length -lt 1) {'notsyncing'}
		else {"other"}
	} | ForEach-Object {
		if ($_ -in $aaccounts) {"AAccount: $_"}
		elseif ($_ -in $demaccounts) {"DemAccount: $_"}
		else {$_}
	} | convertto-json -Compress
	$hw['Chrome'] = $sw_displayname_hash['Google Chrome'] | ForEach-Object {"$($_.displayversion);Auto:$chrome_updatepolicy"}
    $hw['DellSA'] = $sw_displayname_hash['Dell SupportAssist'] | ForEach-Object {$_.displayversion}
	$hw['DellCU'] = $sw_displayname_hash['Dell Command | Update'] | ForEach-Object {$_.displayversion}
	$hw['DellCM'] = $sw_displayname_hash['Dell Command | Monitor'] | ForEach-Object {$_.displayversion}
	try {
		try {$hw['VPro'] = Get-WmiObject -Class "DCIM_VProSettings" -Namespace "ROOT\DCIM\SYSMAN" -ErrorAction SilentlyContinue | ForEach-Object {$_.VProCharacteristics -match "2|3|4|5"}}
		catch {$hw['VPro'] = "err"}
		# $hw['VPro'] = Get-CimInstance -Namespace root -Class __Namespace | where-object Name -eq DCIM | foreach {
		# 	get-cimclass -namespace root\dcim\sysman -class DCIM_VProSettings -erroraction silentlycontinue | 
		# 		ForEach-Object { get-CimInstance -namespace root\dcim\sysman -class DCIM_VProSettings -erroraction silentlycontinue | 
		# 			ForEach-Object {[int]$($_.VProCharacteristics) -match "2|3|4|5"}
		# 		}
		# 	}
	}
	catch {
		$hw['VPro'] = 'fail'
	}
	$dropbox_installed = $sw_displayname_hash['Dropbox'] | ForEach-Object {$_.displayversion}
	$dropbox_lastsync = Get-ChildItem C:\ProgramData\Dropbox\Update\Log | Sort-Object LastWriteTime | Select-Object -last 1 | ForEach-Object {get-date $_.lastwritetime -format s}
	$dropbox_folder = Get-ChildItem C:\Users\*\Dropbox* | ForEach-Object {$_.name} | Group-Object | ForEach-Object {$_.name} | Out-String
	$hw['Dropbox'] = "$($dropbox_installed); $($dropbox_lastsync); $($dropbox_folder);"
	$hw['Edge'] = $sw_displayname_hash['Microsoft Edge'] | ForEach-Object {$_.displayversion}
	# $hw['EdgeSearch'] = Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Preferences" -ErrorAction SilentlyContinue | ForEach-Object {
	# 		$file = Get-Content $PSItem | convertfrom-json
	# 		$file.default_search_provider.search_url -match 'Google'
	# 	} | Group-Object | ForEach-Object {"$($PSITem.name): $($PSItem.count)"} 
	$hw['Extron'] = $sw | Where-Object {$_.Publisher -match 'Extron'} | ForEach-Object {"$($_.displayname);"} | convertto-json -Compress
	$hw['JRE'] = $sw | Where-Object {$_.displayname -match 'Java 8 Update'} | ForEach-Object {"$($_.displayversion);$((Invoke-Command {
		Get-HKEY -path "HKLM:\Software\Policies\Google\Chrome\AutoOpenAllowedForURLs\" -Name 1
		Get-HKEY -path "HKLM:\Software\Policies\Google\Chrome\AutoOpenFileTypes\" -Name 1 
	}) -join ",")"}
	$hw['FileZilla'] = $sw | Where-Object {$_.displayname -match 'FileZilla'} | ForEach-Object {"$($_.displayversion)"}
	$firefox_updates = Get-ChildItem "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js" | ForEach-Object {
		$file = $_.FullName
		$regexTrue = 'user_pref\("app.update.enabled", true\);'
		$updateon = (Get-Content $file) -match $regexTrue | ForEach-Object {$true}
		$updateon
	} | Group-Object | ForEach-Object {$_.name} | out-string
	$hw['Firefox'] = $sw | Where-Object {$_.displayname -match 'Mozilla Firefox'} | ForEach-Object {"$($_.displayversion);Auto:$($firefox_updates)"}
	
	$firewallpolicies = Get-MDMFirewallRules
	# $firewallpolicies | ForEach-Object {
	# 	$name_clean = $PSItem.name -replace "(|)",""
	# 	$PSItem | Add-Member -MemberType NoteProperty -Name PartitionKey -Value $env:computername -Force
	# 	$PSItem | Add-Member -MemberType NoteProperty -Name RowKey -Value $name_clean -Force
	# 	Publish-AzITSTableRow -logentry $PSItem -table SettingsFirewallPolicy | ForEach-Object {$_.StatusCode}
	# 	try {
	# 		$LAitsExists = Get-Command  -Module Win10ITS -ErrorAction SilentlyContinue | ForEach-Object {$_.name -match 'Publish-AzITSLogAnalytics'}
    #     	if ($LAitsExists) {Publish-AzITSLogAnalytics -logentry $PSItem -table SettingsFirewallPolicy | ForEach-Object {$_.StatusCode} }
	# 	}
	# 	catch {Write-ITSHost "Failed: Publish-AzITSLogAnalytics";$_}
	# } | Group-Object | ForEach-Object {Write-UpdateScreen "Uploaded Firewall Policy Rules: $($_.Name); $($_.count)"}
	
	$firewall = Get-NetFirewallProfile -All | Where-Object {$_.enabled -ne $true} | ForEach-Object {$_.name}
	$firewall_logs = Invoke-Command {
    	Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name "LogDroppedPackets" | ForEach-Object {$_ -match "1"}
    	Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name "LogSuccessfulConnections" | ForEach-Object {$_ -match "0"}
    	Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name "LogFilePath" | ForEach-Object {$_ -match "pfirewalldomain.log"}
    	Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name "LogFileSize" | ForEach-Object {$_ -match "32767"}
	} | Group-Object | ForEach-Object {$_.name}
	$hw['Firewall'] = "Disabled: $firewall; Logs: $firewall_logs; Policies: $($firewallpolicies.count)"
	
	$logentry = @{}
	Get-NetAdapterStatistics | ForEach-Object {$_.pSobject.properties} | Where-Object {$_.name -notmatch "CIM"} | Select-Object name, value | ForEach-Object {
		$logentry[$_.Name] = $_.value
	}
	# $logentry['WiFiInfo'] = $hw['WiFiInfo']
	$logentry['RowKey'] = $hw['RowKey']
	$logentry['PartitionKey'] = $hw['PartitionKey']
	$logentry['WifiInfo'] = $hw['WiFiInfo']
	$netshwlanshowall = netsh wlan show all
	$logentry['BSSID'] = $netshwlanshowall | Where-Object {$_ -match '^\s+BSSID\s+:\s+'} | ForEach-Object {$_ -Replace '^\s+BSSID\s+:\s+',''} | convertto-json -compress
	$logentry['ChannelUtilization'] = $netshwlanshowall | Where-Object {$_ -match "channel utilization"} | ForEach-Object {$_ -Replace '^\s+Channel Utilization:\s+',''} | convertto-json -compress
	$logentry['ConnectedStations'] = $netshwlanshowall | Where-Object {$_ -match "Connected Stations"} | ForEach-Object {$_ -Replace '^\s+Connected Stations:\s+',''} | convertto-json -compress
	Publish-AzITSTableRow -logentry $logentry -table EventsNetworkStats | Out-Null
	
	$globalprotectuser = Get-HKEY -Path "HKCU:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" -Name username | Where-Object {$_ -notmatch "Path DNE"}	
	# if (-not$globalprotectuser) {$globalprotectuser = ""}
	$globalprotectprovider = $null -eq (get-Hkey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{25CA8579-1BD8-469c-B9FC-6AC45A161C18}" -Name Disabled)   #| foreach {$_ -match 1}
	$hw['GlobalProtect'] =  $sw | Where-Object {$_.displayname -match 'GlobalProtect'} | ForEach-Object {"$($_.displayversion);$($globalprotectuser);$globalprotectprovider"}
	# $hw['HDD_Serial'] = Get-WMIObject win32_physicalmedia -ErrorAction SilentlyContinue | ForEach-Object {$_.SerialNumber.trim()} | convertto-json -Compress
	$hw['IE'] = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object {$_.featurename -match "Internet-Explorer-Optional-amd64"} | ForEach-Object {$_.State}
	try {
		$ITunesW = $sw | Where-Object {$_.displayname -match 'itunes'} | ForEach-Object {"Win32:$($_.displayversion)"}
		$itunesM = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {$_ -match 'itunes'} | ForEach-Object {"Modern:$($_.version)"}
	}
	catch{Write-UpdateScreen "Failed iTunes"}
	$hw['ITunes'] = "$ITunesW;$ITunesM"
	$hw['WebexCS'] = $sw | Where-Object {$_.InstallLocation -match 'Cisco Spark'} | ForEach-Object {$_.displayversion} 
	$hw['MobileConnect'] = $sw | Where-Object {$_.displayname -match 'MobileConnect'} | ForEach-Object {$_.displayversion} 
	$hw['MBAM'] = $sw | Where-Object {$_.displayname -match 'Malwarebytes'} | ForEach-Object {"$($_.displayversion)"}
	# $bitness = Get-HKEY -Path "HKLM:\Software\Microsoft\Office\16.0\Outlook" -Name "Bitness" | ForEach-Object {$_ -replace "x",""}
	
	$hw['MMA'] = $sw | Where-Object {$_.displayname -match 'Microsoft Monitoring Agent'} | ForEach-Object {"$($_.displayversion)"}
	
	
	$hw['Office'] = $sw | Where-Object {$_.displayname -match 'Microsoft 365|Office 365 ProPlus|Microsoft Office Professional Plus 2016|Office 16 Click-to-Run'} | Sort-Object installdate | Select-Object -first 1 | ForEach-Object {"$($_.displayversion)"}
	$hw['OfficeRing'] = Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "updatebranch"
	$isclassroom = $env:computername -match "Class|Tablet" -or $($hw['IntuneUPN']) -match "classroom"
	$isshared =  $(	$hw['IntuneUPN']) -match "itsclient|deviceenroll"
	$vnext = Get-HKEY -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" -Name NextUserLicensingLicenseIds
	if ($vnext) {
		$hw['OfficeAct'] = "vNext: $vnext"	
	}
	else {
		$ospp = get-childitem -path "C:\Program Files\Microsoft Office" -Filter ospp.vbs -Recurse | ForEach-Object {$_.fullname}
		$output = cscript.exe $ospp /dstatus
		$licensed = $output -match "---LICENSED" | ForEach-Object {$true}
		$MAK = $output -match "Last 5 characters of installed product key:(.*)" | ForEach-Object {$_.split(":")}|Select-Object -last 1 | ForEach-Object {$_.trim()}
		$overrides = Get-HKEY -Path "HKCU:\Software\Microsoft\Office\16.0\Common\ExperimentEcs\Overrides" -detailed
		$hw['OfficeAct'] = "$($isclassroom -or $isshared);$licensed;$MAK;ORR: $($overrides.count)"	
	}
	if ($isclassroom) {
		$list = 'HDMI|Reaktek|magewell|video|audio|extron|mixer|volume|waves'
		$drivers = Get-AllDrivers | Where-Object {$_.caption -match $list} | ForEach-Object {
			$PSItem | Add-Member -Name Version -Value $_.'driverversion-value' -MemberType NoteProperty -Force
			$PSItem | Add-Member -Name PartitionKey -Value $env:COMPUTERNAME -MemberType NoteProperty -Force
			$PSItem | Add-Member -Name RowKey -Value $_.Caption -MemberType NoteProperty -Force
			$PSItem
		} 
		$drivers | Select-Object devicename, manufacturer, caption, version, partitionkey, rowkey | ForEach-Object {
			Publish-AzITSTableRow -logentry $PSItem -table ClassroomDrivers
			} | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Uploaded to Azure (ClassroomDrivers): $($_.Name); $($_.count)"}
		$driverslist2 = $drivers | ForEach-Object {
			$ModifiedDeviceID = $PSItem.DeviceID -replace "\\", "\\"
			$Antecedent = "\\" + $ENV:COMPUTERNAME + "\ROOT\cimv2:Win32_PNPSignedDriver.DeviceID=""$ModifiedDeviceID"""
			$DriverName = $PSItem.DeviceName
			$DriverID = $PSItem.DeviceID
			Get-WmiObject Win32_PNPSignedDriverCIMDataFile -ErrorAction SilentlyContinue | Where-Object {$_.Antecedent -eq $Antecedent} | ForEach-Object {
				$path = $PSItem.Dependent.Split("=")[1] -replace '\\\\', '\'
				$path2 = $path.Substring(1,$path.Length-2)
				$InfItem = Get-Item -Path $path2
				$Version = $InfItem.VersionInfo.FileVersion
				$rc1 = [PSCustomObject]@{
					Name = $DriverName
					ID = $DriverID
					Path = $path2
					Version = $Version
					PartitionKey = $env:COMPUTERNAME
					RowKey = $path2
				}
				$rc1
			}
		}
		$driverslist2 | ForEach-Object {
            $item = $PSItem
            $item.RowKey = $item.RowKey -replace '{|}|#|\\|&',""
            Publish-AzITSTableRow -logentry $item -table ClassroomDriversExtended
        } | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Uploaded to Azure (ClassroomDriversExtended): $($_.Name); $($_.count)"}
		Get-Service -erroraction silentlycontinue | Where-Object {$_.displayname -match $list } | ForEach-Object {
				$rc1 = [PSCustomObject]@{
					Name = $_.Name
					Description = $_.Description
					BinaryPathName = $_.BinaryPathName
					StartType = $_.StartType
					ServiceName = $_.ServiceName
					Status = $_.Status
					PartitionKey = $env:COMPUTERNAME
					RowKey = $_.ServiceName
				}
				Publish-AzITSTableRow -logentry $rc1 -table ClassroomServices
			}
	}


	$wdagOPT_enabled = Get-WindowsOptionalFeature -Online | Where-Object {$_.featurename -match 'Windows-Defender-ApplicationGuard'} | ForEach-Object {$_.state}
	# $vnext = Get-HKEY -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" -Name NextUserLicensingLicenseIds
	# $wdag = Get-HKEY -Path HKLM:\Software\Microsoft\Hvsi -Name EnablePlatformMode 
	try {
		$wdag = Invoke-Command {
			Get-HKEY -Path "HKLM:\Software\Microsoft\Hvsi" -detailed
			Get-HKEY -Path "HKLM:\Software\WOW6432Node\Microsoft\Hvsi" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\HvsiDeployment" -detailed
			Get-HKEY -Path "HKLM:\Software\Policies\Microsoft\AppHVSI" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\AppHVSI" -detailed
			Get-HKEY -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\NetworkIsolation" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\HVSICSP" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\HVSIGP" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\PolicyManager\Providers\{GUID}\default\device\AppHVSI" -detailed
			Get-HKEY -Path "HKLM:\Software\Microsoft\Enrollments" -detailed
			Get-HKEY -Path "HKLM:\SOFTWARE\Microsoft\ClickToRun\OverRide" -detailed
		}
		$hw['OfficeWDAG'] = $wdag | Where-Object {$_.Name -in @("EnablePlatformMode","AllowAppHVSI")} | Select-Object name, value | convertto-json -compress
	}
	catch {
		$hw['OfficeWDAG'] = "err: $(Get-HKEY -Path HKLM:\Software\Microsoft\Hvsi -Name enableplatformmode)"
	}
	$hw['OfficeWDAG'] = "$($hw['OfficeWDAG']); opt: $wdagOPT_enabled" 
	$hw['OtherAV'] = $sw | Where-Object {$_.displayname -match "McAffee|Norton|Kaspersky|BitDefender|WebRoot|ESET|Trend|F-Secure|Voodoo"} | ForEach-Object {$_.displayname} | convertto-json -compress

	$wdacstatus = Get-ComputerInfo | ForEach-Object {$_.DeviceGuardCodeIntegrityPolicyEnforcementStatus}
	$hw['WDACStatus'] = "$($wdacstatus)"
	
	# Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-removedefinitions -dynamicsignatures" -NoNewWindow -Wait
	# Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-SignatureUpdate"  -NoNewWindow -Wait
	# $date = (Get-MpComputerStatus).PSObject.Properties | Where-Object {$_.name -match 'signature' -and $_.TypeNameOfValue -match 'date'} | ForEach-Object {$_.value} | Group-Object | ForEach-Object {get-date $_.name -format s} | Select-Object -first 1
	# $version = (Get-MpComputerStatus).PSObject.Properties | Where-Object {$_.name -match 'signature' -and $_.name -match 'version'} | ForEach-Object {$_.value} | Group-Object | ForEach-Object {$_.name} | Sort-Object -descending | Select-Object -first 1
	# $CFA = 
	# $hw['Defender'] = "$version : $date"
	
	$filebitness = get-command -module win10its | Where-Object {$_.name -match 'Get-FileBitness'}
	
	$onedrive_ring_constants = @{0="Deferred";4="Insider";5="Production"} # https://admx.help/?Category=OneDrive&Policy=Microsoft.Policies.OneDriveNGSC::GPOSetUpdateRing
	$onedrive_ring = Get-HKey -Path "HKLM:\Software\Policies\Microsoft\OneDrive" -Name GPOSetUpdateRing | ForEach-Object {$onedrive_ring_constants[$_]}
	$onedrive_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy90ZW5hbnRpZCI6IjZjZjU2OGJlLWI4NGEtNGUzMS05ZGY2LTM1OTkwNzU4NmIyNyIsImFwcGlkIjoiM2NmNmRmOTItMjc0NS00ZjZmLWJiY2YtMTliNTliY2RiNjJhIiwiaXNzIjoiSXNzdWVyIiwiYXVkIjoiQXVkaWVuY2UifQ.IC6nqP1o5MH87yz9IwlJCdae5yNJeWPbQa98PMEQ0QA"
	# $its = @('agarrett','aidane','amayers','calrutz','cdroesse','ctolson','ddarrow','droush','dupreya','hornungb','kay','kwint','mjpierre','nswisher','rhoward1','samkat','sudeshna','testaaaaa','tjudice','vdejesus')
	$onedrive_reports = Set-HKey -Path "HKLM:\Software\Policies\Microsoft\OneDrive" -Name SyncAdminReports -PropertyType String -Value 	$onedrive_key | ForEach-Object {$_ -match $onedrive_key}
	$onedrive_ring = Set-HKey -Path "HKLM:\Software\Policies\Microsoft\OneDrive" -Name GPOSetUpdateRing -PropertyType DWORD -Value 4 | ForEach-Object {$onedrive_ring_constants[$_]}
	$onedrive_user = "C:\Users\$($($hw['IntuneUPN']))\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
	$onedrive_machine = "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
	$onedrive_kfm = Get-Hkey -Path HKLM:\SOFTWARE\Policies\Microsoft\OneDrive -Name KFMSilentOptIn | ForEach-Object {$true}
	if (Test-Path $onedrive_user) {
		 $onedrive_version = Get-ChildItem $onedrive_user | Select-Object -expand versioninfo | ForEach-Object {$_.productversion}
		 if ($filebitness) {$onedrive_bitness = Get-FileBitness $onedrive_user | ForEach-Object {$_.targetmachine}}
		 $hw['OneDrive'] = "ring: $onedrive_ring; reports: $onedrive_reports;bit: $onedrive_bitness;ver: $onedrive_version;	kfm: $onedrive_kfm"
	}
	elseif (Test-Path $onedrive_machine){
		$onedrive_version = Get-ChildItem $onedrive_machine | Select-Object -expand versioninfo | ForEach-Object {$_.productversion}
		if ($filebitness) {$onedrive_bitness = Get-FileBitness $onedrive_machine | ForEach-Object {$_.targetmachine}}
		$hw['OneDrive'] = "ring: $onedrive_ring; reports: $onedrive_reports;bit: $onedrive_bitness;ver: $onedrive_version; kfm: $onedrive_kfm"
	}
	else {
		$onedrive_version = Get-ChildItem -Path C:\ -Filter onedrive.exe -recurse -ErrorAction silentlycontinue | Sort-Object lastwritetime | Select-Object -first 1 | ForEach-Object {$_.fullname} | ForEach-Object {$_.productversion}
		if ($onedrive_version) {
			if ($filebitness) {$onedrive_bitness = Get-FileBitness $onedrive_machine | ForEach-Object {$_.targetmachine}}
			$hw['OneDrive'] = "unk; ring: $onedrive_ring; reports: $onedrive_reports;bit: $onedrive_bitness;ver: $onedrive_version; kfm: $onedrive_kfm"
		}
		else {
			$hw['OneDrive'] = 'unk'
		}	
	}
	$hw['Panopto'] = $sw_displayname_hash['Panopto (64-bit)'] | ForEach-Object {$_.displayversion}
	 
	try{
		$PulseSecureW = $sw | Where-Object {$_.displayname -match 'Pulse'} | ForEach-Object {"Win32:$($_.displayversion)"}
		$PulseSecureM = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {$_ -match 'Pulse'} | ForEach-Object {"Modern:$($_.version)"}
	}
	catch{Write-UpdateScreen "PulseSecure Failed"}
	$PSlogs_New = Get-HKEY -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels" -subkeys | Where-Object {$_ -match "Microsoft-Windows-PowerShell|PowerShellCore"} | ForEach-Object {
				Get-HKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$_" -Name "ChannelAccess" 
			} | Group-Object | ForEach-Object {$_.name} | ForEach-Object {$_ -eq 'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)'}
	$PSlogs_Main = Get-HKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell" -Name "CustomSD" | ForEach-Object {$_ -eq 'O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0005;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)'}
	$hw['PowerShellLogs'] = "Main: $PSLogs_main; New: $PSLogs_New"
	$hw['PulseSecure'] =  "$PulseSecureW;$PulseSecureM"
	$hw['PollEv'] = $sw_displayname_hash['Poll Everywhere'] | ForEach-Object {$_.displayversion}  #get-sw | Where-Object {$_ -match 'Poll Everywhere'} | sort installdate -Descending | select -first 1 | ForEach-Object {"$($_.displayversion)"}
	$hw['Slack'] = get-sw | Where-Object {$_.displayname -match "slack"} | ForEach-Object {$_.installdate}
	$hw['Szip'] = $sw_displayname_hash['7-zip'] | ForEach-Object {$_.displayversion}  #$sw | Where-Object {$_.displayname -match '7-zip'} | ForEach-Object {"$($_.displayversion)"}
	$teamsautostart = Get-ChildItem -Path "C:\Users\" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
		$TeamsConfig = "$($PSItem.FullName)\AppData\Roaming\Microsoft\Teams\desktop-config.json"
			If (Test-Path $TeamsConfig) {
				$TeamsConfigData = Get-Content $TeamsConfig -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
				$TeamsConfigData.appPreferenceSettings.openAtLogin
			} 
		} | Group-Object | ForEach-Object {"$($_.name): $($_.count)"}
	$hw['Teams'] = $sw_displayname_hash['Teams Machine-Wide Installer'] | ForEach-Object {"$($_.displayversion);autostart:$($teamsautostart);BGs:$(Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Teams\Backgrounds\Uploads\*.* | Measure-Object | ForEach-Object {$_.count})"}
	$hw['Teamviewer'] = $sw | Where-Object {$_ -match "teamviewer"} | ForEach-Object {
		if ($_.installsource -match "Full") {$type = "full"}
		if ($_.installsource -match "Host") {$type = "host"}
		"$type;$($_.displayversion)"
		Set-HKEY -Path "HKCU:\Software\TeamViewer" -Name LockRemoteComputer -Value "0x1" -PropertyType DWORD | Out-Null
	}

	$hw['Thunderbird'] = $sw | Where-Object {$_.displayname -match 'thunderbird'} | ForEach-Object {"$($_.displayversion);$($_.installdate);$($_.installdate)"}
	try { # https://twitter.com/alexverboon/status/1251855185078558721/photo/1
		$hw['TPM'] = &"C:\Windows\System32\TpmTool.exe" getdeviceinformation | ConvertFrom-String -Delimiter ":" | Where-Object {$_.p1 -match "-TPM Has|-TPM Firmware|tpm.FAIL"}| ForEach-Object {$_.p2.trim()}
	} 
	catch {
		Write-UpdateScreen "TPMTool Failed"
	}
	$hw['VLC'] = $sw | Where-Object {$_.displayname -match 'VLC'} | ForEach-Object {"$($_.displayversion)"}
	
	$hw['Winget'] = Find-InPath winget | ForEach-Object {$true}
	
	
	Get-ChildItem "C:\Users\*\AppData\Roaming\Zoom\data\zoom.us.ini" -ErrorAction SilentlyContinue | ForEach-Object {
		$file = $_.FullName
		$regexFalse = 'enable.memlog.file=false'
		$regexTrue = 'enable.memlog.file=true'
		$updateoff = Get-Content $file | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match $regexFalse}
		$noupdate = $null -eq (Get-Content $_.fullname | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match "enable.memlog.file"})
		if ($noupdate) {
			# Add-Content $file "enable.memlog.file=true`n"
			$zoomMem = $null
		}
		if ($updateoff) {
			# (Get-Content $file) -replace $regexFalse, $regexTrue | Set-Content $file    
			$zoomMem = $false
		} 
		if ($updateon) {
			$zoomMem = $true
		}
		$regexFalse = 'zoom.show.crash.report=false'
		$regexTrue = 'zoom.show.crash.report=true'
		$updateoff = Get-Content $file | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match $regexFalse}
		$updateon = Get-Content $file | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match $regexTrue}
		$noupdate = $null -eq (Get-Content $_.fullname | ForEach-Object {$_ -split "`n"} | Where-Object {$_ -match "zoom.show.crash.report"})
		if ($noupdate) {
			# Add-Content $file "zoom.show.crash.report=true`n"
			$zoomCrash = $null
		}
		if ($updateoff) {
			# (Get-Content $file) -replace $regexFalse, $regexTrue | Set-Content $file    
			$zoomCrash = $false
		} 
		if ($updateon) {
			$zoomCrash = $true
		}
	}
	$zoomVer = $sw_displayname_hash['Zoom'] | ForEach-Object {$_.displayversion}
	$hw['Zoom'] = "ver: $($zoomVer); crash: $($zoomCrash); mem: $($zoomMem)"
	
	# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Zoom\Zoom Meetings\Meetings" -name AutoEnableDualMonitor -ErrorAction SilentlyContinue
	# $zoomdual = Get-HKEY -Path "HKLM:\SOFTWARE\Policies\Zoom\Zoom Meetings\Meetings" -name AutoEnableDualMonitor
	# if ($null -eq $zoomdual) {	$hw['r_ZoomDual'] = "PolicyRemoved"}
	# else {$hw['r_ZoomDual'] =$zoomdual}
	# $perfchecks.add($(Get-PerfCheck -ScriptLine $(MyI | foreach {$_.ScriptLineNumber}) -Description $($process.startinfo.filename))) | Out-Null #| Wait-Process -Timeout 60 
	
	# $hw['dock'] = Get-WmiObject -List | Where-Object {$_.__NAMESPACE -eq 'root\cimv2' -and $_.__CLASS -eq 'win32_PNPEntity'} | Where-Object {$_.Name -eq "Generic SuperSpeed USB Hub"} | ForEach-Object {$_.present}
	# $sw | Where-Object {$_.displayname -match "Dell OpenManage Inventory Agent"} | ForEach-Object {
	# 	$hw['dock'] = gwmi -n root\dell\sysinv dell_softwareidentity | Where-Object {$_.elementname -match "Dell"} |ForEach-Object {$_.elementname} | convertto-json
	# 	}

	Write-UpdateScreen 'report to Azure' | ForEach-Object {$($perfchecks.add($(Get-PerfCheck -ScriptLine $(Get-MyI).scriptlinenumber -Description $($PSItem))) | Out-Null);$PSItem}
	$hw['z_CPUpct'] = get-process -Id $pid | ForEach-Object {
            $TotalSec = (New-TimeSpan -Start $_.StartTime).TotalSeconds
            [Math]::Round( ($_.CPU * 100 / $TotalSec), 2)
        }
	$hw['z_PeakWS'] = get-process -Id $pid | ForEach-Object {[math]::Round($_.peakworkingset64/1MB,0)}	
    $hw['z_Runtime'] = [Math]::Round($runtime.elapsed.TotalMinutes,2)
	$avgCPU = $perfchecks.cpupct | Measure-Object -average | ForEach-Object {$_.average}
	$avgRAM = $perfchecks.rampct | Measure-Object -average | ForEach-Object {$_.average}
	$hw['z_perfall'] = $perfchecks | out-string
	$hw['z_perfCPU'] = [math]::Round($avgCPU,0) 
	$hw['z_perfRAM'] = [math]::Round($avgRAM,0) 
	Copy-Item $transcript $jobdonepath -Force
	$hw['z_jobdone'] = Get-ChildItem "C:\Penn Law ITS\Scripts\$($ScriptName.replace('.ps1','')).txt" -ErrorAction SilentlyContinue | ForEach-Object {get-date $_.LastWriteTime -format s}
    # Publish-AzITSTableRowPrivate -logentry $hw -table $itsallTable | foreach {$_.StatusCode} | group | foreach {Write-UpdateScreen "Uploaded to Azure ($itsalltable): $($_.Name); $($_.count)"}
	Publish-AzITSTableRow -logentry $hw -table $itsallTable | ForEach-Object {$_.StatusCode} | Group-Object | ForEach-Object {Write-UpdateScreen "Uploaded to Azure ($itsalltable): $($_.Name); $($_.count)"}

	$CustomerId = "339f92f7-1b8e-42c0-a2c2-f8ddaae94ddf"  
	$SharedKey = "lAUfIqzvHGheSkClbmWOi63VdyVP8zdwMkqHdzk8hQlo9fiZxPy6Ip0tX8NspL+r093tm45fRWfVaVFgE5ViDw=="
	$logType = $itsalltable
	$TimeStampField = ""
	$RequestBody = ConvertTo-Json -InputObject $hw -depth 9 -ErrorAction SilentlyContinue
	
	#Defining method and datatypes
	$method = "POST"
	$contentType = "application/json"
	$resource = "/api/logs"
	$date = [DateTime]::UtcNow.ToString("r")
	$contentLength = $RequestBody.Length
	
	#Construct authorization signature
	$xHeaders = "x-ms-date:" + $date
	$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
	$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
	$keyBytes = [Convert]::FromBase64String($sharedKey)
	$sha256 = New-Object System.Security.Cryptography.HMACSHA256
	$sha256.Key = $keyBytes
	$calculatedHash = $sha256.ComputeHash($bytesToHash)
	$encodedHash = [Convert]::ToBase64String($calculatedHash)
	$signature = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
	
	#Construct uri 
	$uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

	$headers = @{
		"Authorization"        = $signature;
		"Log-Type"             = $logType;
		"x-ms-date"            = $date;
		"time-generated-field" = $TimeStampField;
	}
	#Sending data to log analytics 
   try {
		Invoke-RestMethod -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $RequestBody -UseBasicParsing			
	}
	
	catch { 
		Write-Error "An exception was caught: $($_.Exception.Message)"
		$_.Exception.Response
		if (Test-Path "C:\Users\Droush")  {
			$headers
			$RequestBody
			throw
		}  
	}

	
	Exit 0
}

catch
{
    $_
	Publish-AzITSTableRow -logentry $hw -table $itsallTable -catch $_ 
	Exit 1
}
finally {
	Write-UpdateScreen "Finally Block: Exiting" 
    $ErrorActionPreference = "Continue"
    try{
        stop-transcript|out-null
      }
      catch [System.InvalidOperationException]{Write-UpdateScreen "Failed in Finally"}
}


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4XbJhib7hB8HRrGRRK778fG/
# d4+gggNOMIIDSjCCAjKgAwIBAgIQOkc97gsleplN8l0O0Ma6dDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUdsDDaOfHXtSE4IbwIMVYvvRX
# wuEwDQYJKoZIhvcNAQEBBQAEggEAPjnQiIzlFbUL1FcIXsLPlK/2IpQyrPi7ZeTv
# GwBTvUTKaXBVynBBtAjPZF0t+yWUBFt/k8jgp9BYPww7vbw+dM/K3sYd+dbZzPVf
# bd0/PlEd6fHMRxwOTJrQ4gPrYQPA4l2TmCPd7AP8ILEG/go5R9L9gBeW8BT9yT1d
# AsSovX6brqYEW0FEr4HSOCpQGf8uRxKemaNIPYU48DquNxB5V2NjV3YOUW2N0EWM
# Hmwh1kZr03qfHUYA11Hmr13E/Eqxuh+xw8k5CYp4u/807tPKNxrx5qqXWiI5XA51
# jXbwTXwSzFXL1avIdw8BgOPnPiV1Hdjq/sticjPanHRmY7x0kg==
# SIG # End signature block
