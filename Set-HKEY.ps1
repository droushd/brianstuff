function Set-HKEY {
    <#
    .Synopsis
    Set a registry value in any hive.

    .Description
    This function will create path, name and value for a registry key. Returns value if successful and error if not. 

    .Parameter Path
    The registry Key (AKA folder)  (e.g. "HKLM:\SYSTEM\CurrentControlSet\Control\Power").

    .Parameter Name
    The registry Name (e.g. "ConsentPromptBehaviorUser")

    .Parameter Value
    The registry Value (e.g. 1)

    .Parameter PropertyType
    The data type for the registry value (e.g. DWORD)

    .Parameter CurrentUser
    If $true just change for current user; if $false, change for all users + default user

    .Example
    # Returns True if SMB1 is disabled
    Set-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 

    .Example
    Set-HKEY -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\SlideShow\" -Name "DisableHardwareAcceleration" -Value 1

    #>

    Param(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$Path,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$Name,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$Value,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$PropertyType,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$CurrentUser,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$SpecificUser
      )
    Begin {
        New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
        if (!$PropertyType) {$PropertyType = "String"}
        $checkCU = Get-Variable -Name CurrentUser
        if ($checkCU) {}
        else {$CurrentUser = $false}
        }
    Process
      {
        if ($Path -match "HKCU:") {

            # These hives are not already loaded; will require admin
            if ($CurrentUser) {
                $registryPath = $Path
                if (-not(Test-Path $registryPath)) {New-Item $registryPath -Force | ForEach-Object {Write-Verbose $_} }
                New-ItemProperty $registryPath -Name $Name -Value $Value -PropertyType $PropertyType -Force | ForEach-Object {Write-Verbose $_}
                Get-HKEY -Path $registryPath -Name $Name -CurrentUser $CurrentUser
            }
            elseif (Test-Admin) {
                $Path = $Path -replace 'HKCU:',"" # this allows us to load it w diff path below
                if ($specificuser) {
                    $ProfileList = Get-ProfileList | Where-Object {$_.sid -match $SpecificUser -or $_.username -match $SpecificUser}
                }
                else {
                    $ProfileList = Get-ProfileList | Where-Object {$_.userhive -match 'C:\\Users'}# Get Username, SID, and location of ntuser.dat for all users
                }
    
                $checkit = @()
                # These hives are already loaded            
                $checkit += $ProfileList | Where-Object {$_.userhive -notmatch 'Windows' -And $PSItem.Loaded -eq $True} | ForEach-Object {
                    $registryPath = "registry::HKEY_USERS\$($PSItem.SID)$Path"
                    if (-not(Test-Path $registryPath)) {New-Item $registryPath -Force | ForEach-Object {Write-Verbose $_} }
                    New-ItemProperty $registryPath -Name $Name -Value $Value -PropertyType $PropertyType -Force | ForEach-Object {Write-Verbose $_}
                    Get-HKEY -Path $registryPath -Name $Name
                }                
    
                $checkit += $ProfileList | Where-Object {$_.userhive -notmatch 'Windows' -And $PSItem.Loaded -eq $False } | ForEach-Object {
                    Write-Verbose $PSItem
                    reg load HKU\$($PSItem.SID) $($PSItem.UserHive) | ForEach-Object {Write-Verbose $_}
                    $registryPath = "registry::HKEY_USERS\$($PSItem.SID)$Path"
                    if (-not(Test-Path $registryPath)) {New-Item $registryPath -Force | ForEach-Object {Write-Verbose $_}}
                    New-ItemProperty $registryPath -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
                    Get-HKEY -Path $registryPath -Name $Name
                    [gc]::collect()
                    Start-Sleep -Seconds 2    
                    reg unload HKU\$($PSItem.SID) | ForEach-Object {Write-Verbose $_}
                }
                reg load HKU\DefaultUser C:\Users\Default\ntuser.dat  | ForEach-Object {Write-Verbose $_}
                $registryPath = "registry::HKEY_USERS\DefaultUser$Path"
                if (-not(Test-Path $registryPath)) {New-Item $registryPath -Force  | ForEach-Object {Write-Verbose $_}}
                New-ItemProperty $registryPath -Name $Name -Value $Value -PropertyType $PropertyType -Force  | ForEach-Object {Write-Verbose $_}
                $checkit += Get-HKEY -Path $registryPath -Name $Name
                [gc]::collect()
                Start-Sleep -Seconds 2
                reg unload HKU\DefaultUser  | ForEach-Object {Write-Verbose $_}
                $checkitR = $checkit | Group-Object | ForEach-Object {$_.name}
                return $checkitR    
            }
            else {
                "Error condition"
            }           
        }
        else {
            if (Test-Admin) {
                if (-not(Test-Path $Path)) {New-Item $Path -Force | Out-Null}
                New-ItemProperty -Path $Path -Name $name -Value $value -PropertyType $PropertyType -Force | Out-Null
                $checkit = Get-HKEY -Path $Path -Name $Name 
                return $checkit
            }
            else {return "Failed: process requires admin privileges to continue"}
        }
    }
    End {
        Remove-PSDrive -Name HKCR | Out-Null
    }
} # End Function Set-HKEY




# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8nT/PZH8SXoQW8zG+AhrfK+y
# 1/qgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQURlHGbKF8yAfY9JW9Xh7KMYjb
# Ja4wDQYJKoZIhvcNAQEBBQAEggEALa+eMvn7LiO5M7iSQHB7LdZEaBQ9a39O/1fO
# 2M0qeNSzEXUCPOSMCQzczclxzE6K06/rFQ0g4OTzyMdLdamxl0Cs23fK5CjWXjTR
# 7GZkX/+KIye2warGwJs0cN28zVoU2Hzz1vf76tnkEPhFjPG+8PzCHGSltFm6DFqF
# vuNPk6aPoCTL6HSFvJC8jvPG95LVr4BBS+ldnVPiFEhy4QTH8C1NGuzqGKdnpRyo
# nUzIy9gRW8EmU98octdMqkvt6BVXkm5H+s8qK7STSbL/7R2aE4PxCmwPERYR6hzw
# 9D5q5vVfJkf5oNIqsn9DYtEfPKtO4YHXElv5sgUkO5hTvH6rVg==
# SIG # End signature block
