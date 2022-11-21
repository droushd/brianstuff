Function Get-AllDrivers {
    <#
    .Synopsis
    This function collects driver information, and returns a PSCustomObject.

    .Description
    Uses WMI Win32_PnPEntity and Win32_PnPSignedDriver
    .Example
    # Get Intel Drivers 
    Get-AllDrivers | where {$_.Manufacturer -matches 'Intel'}

    #>

    $StatusLookup = [System.Collections.Generic.List[PSObject]]::New()
    $PnPEntity = Get-CimInstance -Class Win32_PnPEntity -Filter 'ConfigManagerErrorCode = 0' 
    $PnPdriverAll = Get-CimInstance -Class Win32_PnPSignedDriver
    $PnPdriverAll_hash = @{}
    $PnPdriverAll | & {process {$PnPdriverAll_hash[$($PSItem.deviceID)] = $($PSItem) } }
    $PnPEntity | foreach {
        $entity = $PSItem
        $myRow = [PSCustomObject]@{}
        # Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name  DeviceID -Value $entity.DeviceID
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name  Caption -Value $entity.caption 
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name  Status -Value $entity.status
        $PnPdriver = $PnPdriverAll_hash["$($_.deviceID)"]
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name DeviceID -Value $PnPdriver.DeviceID
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name ClassGUID -Value $PnPdriver.ClassGUID
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name CompatID-Value $PnPdriver.CompatID
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name DeviceName -Value $PnPdriver.DeviceName 
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name DriverVersion-Value $PnPdriver.DriverVersion
        Add-Member -InputObject $myRow -MemberType NoteProperty -Force -Name Manufacturer -Value $PnPdriver.Manufacturer
        $StatusLookup.Add($myRow)
    }
    return $StatusLookup
} # End Function Get-AllDrivers


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcp0N2+170SewUmHiy+Q1Fq3z
# X5mgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUM+rMZYI2FWaIbZrn77MIdDqq
# y2gwDQYJKoZIhvcNAQEBBQAEggEAXijCTNvtoXaO0C2aFR9RQrw839LK9E71ZCr9
# EA0MMUg5RGW46znJt2GHSOQeEkCe1s9cKpOBpDgtnyZOp4XG4zSzTkUFvjPJ3ie4
# DH9hl7ayMdYPPuWV2JMdhLTyllHPSRR7Npv7ws1IxwQFMyzDDBa34Eb4Ut5xPCDy
# b+CVwBCuiUP7zrCsVZtbSXiELFOP3JadLSs7T9WVh87bO+oueSKHV2y9mKoW+DSx
# LTejR+w3uQXl+GmtPKKY19OI9DwVUGqFyCvDoSYEensXVFMFRSxMzXzZzpB0cvTD
# QHl7uYDVErtZhZmyzdORmqQww9xTMu7bd+L2npfBKQe0sf602A==
# SIG # End signature block
