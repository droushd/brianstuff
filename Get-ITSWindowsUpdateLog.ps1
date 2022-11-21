Function Get-ITSWindowsUpdateLog {
    [CmdletBinding(
    	HelpURI="https://github.com/PennLawITS/Win10ITS",
    	SupportsShouldProcess=$true
	)]
    [OutputType([Object])]
	Param (
		[Parameter(Mandatory=$False)][switch]$upload
	)

    $logpath = "$env:temp\WindowsUpdate$(Get-Date -format "MM-dd-yyyy-HH-mm-ss").log"
    # $ProgressPreference = "SilentlyContinue"
    Get-WindowsUpdateLog -LogPath $logpath | Out-Null
    $x = 0
    $WindowsUpdateLog = Get-Content $logpath
    $WindowsUpdateLogPARSED = $WindowsUpdateLog | ForEach-Object {
        $length = $PSItem.length
        [pscustomobject]@{
            Date = $PSItem.substring(0,10).Trim()
            Time =  $PSItem.substring(11,16).Trim()
            ID1 = $PSItem.substring(28,4).Trim()
            ID2 = $PSItem.substring(34,4).Trim()
            FieldX = $PSItem.substring(40,16).Trim()
            Description = $PSItem.substring(56,$($length)-56).Trim()
            Row = $x
        }
        $x+=1
    } | ForEach-Object {
        $dateTime = Get-Date "$($_.Date) $($_.Time)" -format o
        # Add-Member -InputObject $PSItem -Name DateTime -Value $dateTime -MemberType NoteProperty -Force
        Add-Member -InputObject $PSItem -Name PartitionKey -Value $env:COMPUTERNAME -MemberType NoteProperty -Force
        Add-Member -InputObject $PSItem -Name RowKey -Value $DateTime -MemberType NoteProperty -Force
        $PSItem
    }
    $KBLogs = $WindowsUpdateLogPARSED | Where-Object {$_.description -match "KB" -And $_.Description -match "Title =" -And $_.Description -notmatch "Security Intelligence Update for Microsoft Defender Antivirus"} | ForEach-Object {
        $nextrow = $PSItem.Row
        $updateID = $WindowsUpdateLogPARSED[$nextrow+1].Description
        $updateID = $updateID -split "="| Select-Object -last 1 | ForEach-Object {$_.trim().ToUpper()}
        Add-Member -InputObject $PSItem -Name UpdateID -Value $updateID -MemberType NoteProperty -Force
        $PSItem.Description = $PSItem.Description -Replace "Title = ", ""
        $PSItem
    }
    $Win11Logs = $KBLogs | Where-Object {$_.description -match "Windows 11"} | Group-Object UpdateID | ForEach-Object {
        $UpdateID = $_.Name
        $Title = $_.Group[0].Description
        $WindowsUpdateLogPARSED | Where-Object {$_.description -match $UpdateID }  | Select-Object -Exclude Row,Date,Time | ForEach-Object {
            Add-Member -InputObject $PSItem -Name UpdateID -Value $updateID -MemberType NoteProperty -Force
            Add-Member -InputObject $PSItem -Name Title -Value $Title -MemberType NoteProperty -Force
            $PSItem
        }
    }
	$AllKBLogs = $KBLogs | Group-Object UpdateID | ForEach-Object {
        $UpdateID = $_.Name
        $Title = $_.Group[0].Description
        $WindowsUpdateLogPARSED | Where-Object {$_.description -match $UpdateID }  | Select-Object -Exclude Row,Date,Time | ForEach-Object {
            Add-Member -InputObject $PSItem -Name UpdateID -Value $updateID -MemberType NoteProperty -Force
            Add-Member -InputObject $PSItem -Name Title -Value $Title -MemberType NoteProperty -Force
            $PSItem
        }
    }

    $output = [PSCustomObject]@{
        Win11 = $Win11Logs
        KB = $KBLogs
        All = $WindowsUpdateLogPARSED
		AllKB = $AllKBLogs
    }
    if ($upload) {
        $hw = Get-Inven -basic
        $AllResults = $output.allKB | ForEach-Object {
			Add-Member -InputObject $PSItem -Name A_IntuneUPN -Value $hw['IntuneUPN'] -MemberType NoteProperty -Force
			Add-Member -InputObject $PSItem -Name A_IntuneID -Value $hw['IntuneID'] -MemberType NoteProperty -Force
			Add-Member -InputObject $PSItem -Name A_AzureADDeviceID -Value $hw['AzureADDeviceID'] -MemberType NoteProperty -Force
			Add-Member -InputObject $PSItem -Name A_Model -Value $hw['Model'] -MemberType NoteProperty -Force
			Add-Member -InputObject $PSItem -Name A_OSBuild -Value $hw['OSBuild'] -MemberType NoteProperty -Force
			$PSItem
		}
		$AllResults | ForEach-Object {
			Publish-AzITSTableRow -logentry $PSItem -table 'UpdatesWindows11' | Out-Null
		}
    }
    return $output
}



# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuxzCe68F7I68TCw8NbM5VyWa
# phqgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUf9D8h8CiI+AbvS5zryF6AOlc
# TtswDQYJKoZIhvcNAQEBBQAEggEAJlCon7xxSM6zdoZy9xrio/SJq+ymQpRHxKCY
# hbuojMGIUw3HWeXY9Rtfz+nbZ9S4hVXt8MpZ8ds65wt59VUdfDaSGERWIBBVOG4O
# x77hKCUh1hkskl5Xpm+wsB9KOhnLHimt067/AY09pCxzsUmq3zFKExZ1PlLyJPaU
# BqpMrbID6xlsh1re/5IpjSNVcsJyjmNCcMfyeYNYHeCMH+hF96p3WT0A8Elo/Odj
# amzONZE27lbpls1uOEuCGbKCeCZzZC/Zn4fSXLpSeMfA7fgeOZzcEdR+NUFRIX87
# lDGFUsxqvPWHDWoB8rtuNFUUBh/ctV4VI3VbNEu6AdFZ7jcW+w==
# SIG # End signature block
