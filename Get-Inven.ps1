function Get-Inven {
    <#
    .Synopsis
    Collect system information for use in scripts/azure.

    .Description
    This first runs Get-InvenBasic, which creates $hw variable.

    .Example
    # Run the function and show the output in JSON format.
    Get-InvenExtended
    $hw | convertto-json

    .Parameter basic
    Get only the basic inventory data

    .Parameter pscustomobject
    Return the information as PSCustomObject (default is hashtable)

    #>
    Param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Switch]$basic,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Switch]$upn,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$ordered,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Switch]$pscustomobject
    )
    
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $private:ErrorActionPreference = "SilentlyContinue"
        $private:hw = New-Object 'system.collections.generic.dictionary[string,string]'
    }


    Process {
        Function Convert-UTCtoLocal {
            param( [parameter(Mandatory=$true)] [String] $UTCTime )
            $strCurrentTimeZone = "Eastern Standard Time"
            $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
            $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ) 
            return $LocalTime
        }
            
        #Get Intune DeviceID and ManagedDeviceName
        if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
            $MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
            $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
        }
        $ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
        $hw['IntuneID'] = $ManagedDeviceInfo.EntDMID
        $intune = $ManagedDeviceName -split "_" 
        $hw['IntuneUPN'] = $intune[0]
        $hw['IntuneDate'] = get-date $(Convert-UTCtoLocal "$($intune[2]) $($intune[3])") -format s
        
        if ($upn) {return}
        # get hardware info
        $computerSystem = Get-CimInstance -class CIM_ComputerSystem -namespace "root\CIMV2"
        $hw["ComputerName"]=$computerSystem.Name
        $hw["Manufacturer"]=$computerSystem.Manufacturer
        $hw["Model"]=$computerSystem.Model

        $hw["SerialNumber"]=  Get-CimInstance -class CIM_BIOSElement -namespace "root\CIMV2"  | ForEach-Object {$_.SerialNumber}
        
        $computerOS = Get-CimInstance -class CIM_OperatingSystem -namespace "root\CIMV2"
        $osHash = @{
            10240 = "T1"
            10586 = "T2"
            14393 = "R1"
            15063 = "R2"
            16299 = "R3"
            17134 = "R4"
            17763 = "R5"
            18362 = "19H1"
            18363 = "19H2"
            19041 = "20H1"
            19042 = "20H2"
            19043 = "21H1"
            19044 = "21H2"
            22000 = "Win11"
            22621 = "22H2"
        }
        $insider = $osHash.keys | Sort-Object -desc |Select-Object -first 1
        if ([double]$computeros.BuildNumber -gt [double]$insider) {$hw['OSBuild']='insider'}
        else {$hw['OSBuild'] = $oshash[$([int]$computeros.BuildNumber)]}
        $ppf = $ProgressPreference
        $ProgressPreference = "Silentlycontinue"
        $hw['OSDate'] = get-computerinfo | ForEach-Object {get-date $_.WindowsInstallDateFromRegistry -format s}
        $ProgressPreference = $ppf
        try {		
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = "c:\windows\system32\dsregcmd.exe"
            $pinfo.RedirectStandardError = $true
            $pinfo.RedirectStandardOutput = $true
            $pinfo.UseShellExecute = $false
            $pinfo.Arguments = " /status"
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $pinfo
            $p.Start() | Out-Null
            $stdout = $p.StandardOutput.ReadToEnd()
            # $stderr = $p.StandardError.ReadToEnd()
            $AzureAdJoined = $stdout -split "\r" | Where-Object {$_ -match 'AzureAdJoined'} 
            if ($AzureAdJoined -match "YES") {
                $hw['AzureADDeviceID'] =  $stdout -split "\r" | Where-Object {$_ -match 'DeviceId'} | ForEach-Object {$_ -split ":"} | Select-Object -last 1 | ForEach-Object {$_.trim()}
                # $hw['AzureADDeviceID'] =  $stdout | convertfrom-string | where {$_.p2 -match 'deviceid'} | foreach {$_.p4}
            } 
        }
        catch {
            $hw['AzureADDeviceID'] = "error"
            Publish-AzITSTableRow -logentry $hw -table "ScriptErrorLogging" -catch $_ -iserror $true
        }

        $hw['AzureADUsers'] = Get-ProfileList | Where-Object {$_.SID -Match "S-1-12"} | ForEach-Object {$_.username} | convertto-json -compress    
        $BatteryStatus = @{
            Name = 'BatteryStatusText'
            Expression = {
                $value = $_.BatteryStatus	  
                switch([int]$value) {
                    1   {'Battery Power'}
                    2   {'AC Power'}
                    3   {'Fully Charged'}
                    4   {'Low'}
                    5   {'Critical'}
                    6   {'Charging'}
                    7   {'Charging and High'}
                    8   {'Charging and Low'}
                    9   {'Charging and Critical'}
                    10  {'Undefined'}
                    11  {'Partially Charged'}
                    default {"$value"}
                }
            }  
        }
        if ($($hw['Model']) -notmatch "Optiplex") {
            $hw['PowerStatus'] = Get-CimInstance -ClassName Win32_Battery -Namespace "root/CIMV2" | Select-Object -Property $BatteryStatus,EstimatedChargeRemaining | ForEach-Object {"$($_.BatteryStatusText): $($_.EstimatedChargeRemaining)%"}    
        }  
        elseif ($($hw['Model']) -match "Optiplex") {
            $hw['PowerStatus'] = "AC"
        }
        else {
            try {
            $powerlinestatus = [System.Windows.Forms.SystemInformation]::PowerStatus | ForEach-Object {if($_.powerlinestatus -match 'Online'){"AC"}else{"Battery"}}
            $hw['PowerStatus'] = "$($powerlinestatus)"
            }
            catch {$hw['PowerStatus'] = 'err'}
        }
        if ($basic) {
            return
        }


        $hw["CPU"]=  Get-CimInstance -class CIM_Processor -Namespace "root\CIMV2" | ForEach-Object {$_.Name} 
        $hw["GPU"]=  Get-CimInstance -class CIM_VideoController -Namespace "root\CIMV2" | ForEach-Object {$_.Name} 
        $hw['HDD_Serial'] = Get-CIMInstance win32_physicalmedia | ForEach-Object {$_.SerialNumber.trim()} | convertto-json -Compress
        Get-CimInstance -class Win32_LogicalDisk -namespace "root\CIMV2" -Filter "DeviceID = 'C:'" | ForEach-Object {
            $hw["HDD_Capacity"]=[Math]::round($PSItem.Size/1GB,0) 
            $hw["HDD_Free"]=[Math]::round($PSItem.FreeSpace/1GB,0)
            if([double]$PSItem.Size -ne 0){$hw["HDD_Free_Pct"]=[Math]::round($PSItem.FreeSpace/$PSItem.Size,2)}
        }
        $hw["RAM"]= Get-CimInstance -class "win32_physicalmemory" -namespace "root\CIMV2" | ForEach-Object {$_.capacity/1GB} | Measure-Object -sum | ForEach-Object {$_.sum}
        $hw["OS"]=  dism /online /get-currentedition | ForEach-Object {$_ -split "\n"} | Where-Object {$_ -match "^Version"} | ForEach-Object {$_ -split "Version:"} | Select-Object -last 1 | ForEach-Object {$_.trim()}   #[System.Environment]::OSVersion.Version.tostring()
        $hw['Win11'] = Get-ciminstance win32_operatingsystem | ForEach-Object {$_.caption -match 'windows 11'}
        $hw["BIOS"]= Get-CimInstance -class CIM_BIOSElement -Namespace "root\CIMV2" | ForEach-Object {$_.SMBIOSBIOSVersion} 
        $hw['Bitlocker'] = Get-BitLockerVolume C: | ForEach-Object {"$($_.protectionstatus):$($_.VolumeStatus)"} 
            
        $Monitor_Cable = @{
            '-2' ="Uninitialized"
            '-1' ="Other"
            '0' = "HD15"
            '1' = "SVideo"
            '2' = "Composite"
            '3' = "Composite"
            '4' = "DVI"
            '5' = "HDMI"
            '6' = "LVDS"
            '8' = "D_JPN"
            '9' = "SDI"
            '10' = "ExtDP"
            '11' = "EmbDP"
            '12' = "ExtUDI"
            '13' = "EmbUDI"
            '14' = "SDTVDONGLE"
            '2147483648' = "Int"
        }  

        $monitorCCX =  Get-CimInstance -namespace root\WMI -Query "Select * from WmiMonitorConnectionParams" -ErrorAction SilentlyContinue
        $monitorCCX_hash = @{}
        $monitorCCX | Where-Object {$null -ne $_.instancename} | & {process {$monitorCCX_hash[$($PSItem.instancename)] = $($PSItem) } }
                
        $monitors =  Get-CimInstance -namespace root\WMI -Query "Select * from wmiMonitorID" -ErrorAction SilentlyContinue | ForEach-Object {
            $a = $($monitorCCX_hash[$($_.instancename)].videooutputtechnology)
            [PSCustomObject]@{
                MonitorType = $(if ($null -eq $_.UserFriendlyName) {""} else {($_.UserFriendlyName -ne 0 | ForEach-Object {[char]$_}) -join ""})
                MonitorSerial = $(if ($null -eq $_.UserFriendlyName) {""} else {($_.SerialNumberID -ne 0 | ForEach-Object {[char]$_}) -join ""})
                MonitorCCX = $Monitor_Cable["$a"]
            } 
            } | Where-Object {$_.monitorccx -notmatch "int"} | ForEach-Object {
                $temp = $_.psobject.properties | Where-Object {$_.membertype -match "NoteProperty"} | ForEach-Object {$_.value}
                $temp -join ", "
            }
        $hw['Monitors'] = $monitors -join "; "

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

        If ($($hw['Model']) -notmatch "Optiplex") {
            try {
                Add-Type -AssemblyName System.Runtime.WindowsRuntime
                $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
                Function Await($WinRtTask, $ResultType) {
                    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                    $netTask = $asTask.Invoke($null, @($WinRtTask))
                    $netTask.Wait(-1) | Out-Null
                    $netTask.Result
                }
                [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
                [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
                Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
                $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
                $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }
                [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
                # Await ($bluetooth.SetStateAsync($BluetoothStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) 
                $btdevices = Get-PnpDevice -class Bluetooth | Where-Object HardwareID -match 'DEV_' #| Measure-Object | Select-Object -expand count
                $bluetoothconnected = $btdevices | ForEach-Object {
                    $friendlyname = $PSItem.friendlyname
                    Get-PnPDevice | Where-Object -FilterScript { $_.friendlyname -match $friendlyname -And $_.Class -notmatch "Bluetooth|MEDIA|System" -And $_.Present} | Group-Object caption|ForEach-Object {$_.name}} #| measure | select -expand count
                $hw['Bluetooth'] = "$($bluetooth.state): qty $($btdevices | Measure-Object | Select-Object -expand count); ccx $($bluetoothconnected | Measure-Object | Select-Object -expand count)"
            }	
            catch {
                $hw['Bluetooth'] = "err"
            }
        }

        function Get-Domain {
            [CmdletBinding()]
            param([Parameter(Mandatory, Position=0)][String]$Fqdn)
            
            # Create TLDs List as save it to "script" for faster next run.
            # $TldsList_path = "$env:temp\tldlist.txt"
            # $TldsList_exsts = Test-Path $TldsList_path
            # if ($TldsList_exsts) {Get-Content $TldsList_path}
            if (!$TldsList) {
                $TldsListRow = Invoke-RestMethod -Uri https://publicsuffix.org/list/public_suffix_list.dat
                $script:TldsList = ($TldsListRow -split "`n" | Where-Object {$_ -notlike '//*' -and $_})
                [array]::Reverse($TldsList)
            }
            #Remove-Variable TldsList
        
            $Ok = $false
            foreach ($Tld in $TldsList)
            {
                if ($Fqdn -Like "*.$Tld")
                {
                    $Ok = $true
                    break
                }
            }
            #$Tld =  $TldList | Where-Object {$Domain -Like "*.$_"} | Select-Object -Last 1
        
            if ($Ok)
            {
                ($Fqdn -replace "\.$Tld" -split '\.')[-1] + ".$Tld"
            }
            else
            {
            
            }
        }

        # Range from 10.0.0.0 to 10.255.255.255 — a 10.0.0.0 network with a 255.0.0.0 or /8 (an 8-bit) mask
        # Range from 172.16.0.0 to 172.31.255.255 — a 172.16.0.0 network with a 255.240.0.0 or /12
        # A 192.168.0.0 to 192.168.255.255 range, which is a 192.168.0.0 network masked by 255.255.0.0 or /16
        # A special range 100.64.0.0 to 100.127.255.255 with a 255.192.0.0 or /10 network mask; this subnet is recommended according to rfc6598 for use as an address pool for CGN (Carrier-Grade NAT)

        try {$exthost = Invoke-RestMethod http://ifconfig.me/ip -UseBasicParsing | ForEach-Object {[System.Net.Dns]::GetHostbyAddress($PSitem)} | ForEach-Object {get-domain $_.hostname}}
        catch {$exthost = "Error"}

        $hw['IPs'] = Get-CimInstance -namespace ROOT\cimv2 -class win32_networkadapterconfiguration | where-object {$PSItem.ipenabled} | ForEach-Object {
            $ip_private = $($PSItem.ipaddress[0]) -match "^10.|^172.|^192.|^100."
            if ($ip_private) {"privateIP"}
            else {"$($PSItem.ipaddress[0]),$($PSItem.DHCPenabled[0]);"}
            }| Group-Object | ForEach-Object {$_.name} | ConvertTo-Json -Compress
        $hw['IPs'] = "$($exthost): $($hw['IPs'])".Replace('"','')
        $networkcategory = @{
            1	=	"Private"
            0	=	"Public"
            2	=	"Domain"
        }
        $hw['Network'] = Get-CimInstance win32_networkadapter -filter "netconnectionstatus = 2" | ForEach-Object {
            $name = $_.Name
            $isVPN = $Name -match 'PanGP|Pulse'
            $CCXID = $PSItem.NetConnectionID
            if ($PSItem.NetConnectionID -match "Wi-Fi") {
                $wifisignal = (netsh wlan show interfaces) -Match '^\s+Signal ' -Replace '^\s+Signal \s+:\s+',''
                $wifireceive = (netsh wlan show interfaces) -Match '^\s+Receive rate \(Mbps\)' -Replace '^\s+Receive rate \(Mbps\)\s+:\s+',''
                $wifitransmit = (netsh wlan show interfaces) -Match '^\s+Transmit rate \(Mbps\)' -Replace '^\s+Transmit rate \(Mbps\)\s+:\s+',''	
                $wifiradio = (netsh wlan show interfaces) -Match '^\s+Radio type' -Replace '^\s+Radio type\s+:\s+',''
                $wifiprofile = (netsh wlan show interfaces) -Match '^\s+SSID ' -Replace '^\s+SSID \s+:\s+','' 
                $wifichannel = (netsh wlan show interfaces) -Match '^\s+Channel ' -Replace '^\s+Channel \s+:\s+',''                
                if ($wifiprofile -match "AirPennNet|EduRoam") {}
                else {$wifiprofile = "HOME"}
                $hw['WiFiInfo'] = "$($wifiprofile): $($wifiradio): $($wifisignal.trim()), Down: $($wifireceive.trim()),Up: $($wifitransmit.trim()); VPN: $isVPN"	
            }
            get-netconnectionprofile | Where-Object {$PSItem.InterfaceAlias -match $CCXID}  | ForEach-Object {
                $interfacealias = $PSItem.InterfaceAlias
                if ($isVPN) {$alias = "VPN"}
                elseif ($interfacealias -match "Wi-Fi") {$alias = "Wi-Fi"}
                else {$alias = $interfacealias}
                "$($alias), $($networkcategory[$([int]$PSItem.NetworkCategory)])"
            }} | convertto-json
        # $hw['WiFiProfiles'] = (netsh.exe wlan show profiles) -match '\s{2,}:\s' | ForEach-Object {$_ -split ":" | Select-Object -last 1| ForEach-Object {$_.trim()}} | convertto-json -compress
        $hw['MacAddress'] = Get-NetAdapter | Where-Object {$_.macaddress.length -gt 2} | ForEach-Object {$_.macaddress} | convertto-json
        $hw['IP6'] = Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.enabled -eq $True} | ForEach-Object {$_.name} | convertto-json
        
        $hw['WiFi'] = get-netadapter | Where-Object {$_.name -match 'Wi-Fi'} | ForEach-Object {$_.InterfaceDescription}
        # get last boot time
        # Import-module C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Diagnostics\Microsoft.PowerShell.Diagnostics.psd1
        try {
            $value = get-hkey -path HKLM:\SYSTEM\CurrentControlSet\Control\Windows -name shutdowntime
            if ($value) {   
                $hw['LastReboot'] = [DateTime]::FromFileTime([System.BitConverter]::ToInt64($value,0)) | ForEach-Object {Get-Date $_ -format s}
            }
            else {
                $bootTime = Get-WinEvent -FilterHashtable @{logname='System'; id=(12,41,6005) } -ErrorAction SilentlyContinue | Where-Object {$_.providername -match 'Microsoft-Windows-Kernel-General'}  | Sort-Object timecreated -Descending | Select-Object -first 1 
                if ($bootTime) {
                    $hw['LastReboot'] = $bootTime |ForEach-Object {Get-Date $($_.timecreated) -format s}
                }
            }
        }
        catch {
            $hw['LastReboot'] = ""
            }

    }
    end {
        if ($ordered) {
            $deletekey = @()
            $hw.GetEnumerator() | ForEach-Object {$deletekey += $_.key}
            $deletekey | ForEach-Object {
                $newkey = "$($ordered)$($PSItem)"
                $hw[$newkey]=$hw["$PSItem"];
                $hw.remove($PSItem) | Out-Null
            }
        }

        if ($pscustomobject) {
            $logentry = New-Object PSCustomObject
            Add-Member -NotePropertyMembers $hw -InputObject $logentry
            return $logentry
        }
        else {
            return $hw
        }
        }
} #End Function Get-Inven


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4vjtS28qPDQ6T1/KIz7tWubg
# nAygggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
# AQsFADAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbTAe
# Fw0yMjExMjExNDAzMDhaFw0zMjExMjExNDEzMDhaMCgxJjAkBgNVBAMMHXBlbm5s
# YXdzY2hvb2wub25taWNyb3NvZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAmK7TlA3wGi383lYrziQmsQaC0tpReqlPxnox69vP0kj0GxIn7Xdt
# HXL29397iSofjm2p8VqwELDLd/0mNTpCtSFWXz/OMuPAuODAD0QGxp0MPzqMXPsc
# rqW5hS5vXokd4qeqTy3LosW146C6MU3AzUGgYb4gh5EPwSICXOxHipKngbzlZ9hm
# S2MuC3N6Bg7OX7QFm/MCQYeh1va5iSkwNKHZRfB2f2J08R2+DFRCBV3meQm8Y90G
# e0unV4zTWu00abgSleQChpCWh8Clyh+iQ3cns4n51aOzBBKAK1AN+uVpfcaBdZrQ
# EFp48XI+T4GpIv7mipJ1CgnI9JWxCSV25QIDAQABo3AwbjAOBgNVHQ8BAf8EBAMC
# B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwKAYDVR0RBCEwH4IdcGVubmxhd3NjaG9v
# bC5vbm1pY3Jvc29mdC5jb20wHQYDVR0OBBYEFE/11+6yebJM38cjuiupx4JqQTUR
# MA0GCSqGSIb3DQEBCwUAA4IBAQBn8/ORnSajbo4SnQOPYMmGTVEC+Z19//KQodpX
# X2+gJHc07F7uqkux5PwjxLgpccC3INz9Oq8Qxb3DzC1ldv9tYJ4aitSOq1j3LLZL
# rWDgN8sZ8O8fQux6eL70XvV8AOLH1G9xw8IycNkuCI6tgp96hjwxWBf2W6DNYP+x
# 6hwGfafF8n9D+HxdM7coG6dKOvFNFvsUWvTbQZYkHY6/z+ziGk+lmaFO/ABwBxCC
# JSnXvvMKVUqNyLUfmqwxvTbnVhmZVeGkSXlo0dsRhSdDvQmm1MlNAC0YQ9Z/xuNA
# PG0FAnnlTI901FE+8dvtZHd02tRCIHNj0eFbbLKeTxBqkFZUMYIB3TCCAdkCAQEw
# PDAoMSYwJAYDVQQDDB1wZW5ubGF3c2Nob29sLm9ubWljcm9zb2Z0LmNvbQIQIBPn
# tLmZnK5B5G5IDj1xLDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUJryPgorfnU1iaJ6giasUHxIi
# nxIwDQYJKoZIhvcNAQEBBQAEggEAgBXJJgNAyPs6BJfy/vsXcoJ7gLonxyfXOdJd
# NiWIwlb72I/hksdHUwCY89nl4pyv3DURvsccq90+n+k4VG7Z0KPPiBjskHsHNpPG
# +u5boCOr7WEAo9hRKKunK/zwKEskl1MtKpzpiB5wAHhFbBkWjvuIa8q/S9IE5Phq
# G+O7dyq0enn4krnp1MjVuTPGXaqkDS8PgtCTE0ZQwsuEiq5vDdqXI5cN9DbC2Unf
# sxQnvVKfiKPXqe439JME4sDZmTIftDAsPNycLRrJV/U6ToOqpLCRicZR5Lo9tSKU
# GFUFx0/APcVg5/DaRKHHqySLkL8iveBR5O4Xzwi92R6t3KRkXA==
# SIG # End signature block
