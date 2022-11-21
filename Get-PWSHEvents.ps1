Function Get-PWSHEvents {
    Get-WinEvent -LogName "Windows Powershell" | foreach {

        $HostApplication = $_.message.split("`n") | where {$_ -match 'HostApplication'} | foreach {$_.replace('HostApplication=','').trim()}
        $ScriptName = $_.message.split("`n") | where {$_ -match 'ScriptName'} | foreach {$_.replace('ScriptName=','').trim()}
        $CommandLine = $_.message.split("`n") | where {$_ -match 'CommandLine'} | foreach {$_.replace('CommandLine=','').trim()}
        Switch ($hostapplication) {
            {$hostapplication -match "Windows Defender Advanced Threat Protection"}  {$category = "ATP"}
            {$hostapplication -match "Microsoft Intune Management Extension"} {$category = "Intune"}       
            {$hostapplication -match "Microsoft.Office.Desktop"} {$category = "Office"}       
        }
        $timecreated = Get-Date $PSItem.TimeCreated -Format s
        [PSCustomObject]@{ 
            HostApplication = $hostapplication
            Category = $category 
            ScriptName =  $ScriptName 
            CommandLine = $CommandLine 
            TimeCreated = $timecreated
            Message = $PSItem.Message 
            }
    }
    
}





# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJmK1sIqeDSI/rlTtb0HGLBMj
# G/egggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUpA5wtNhdXxc7uDsPrKv3NoTT
# mnwwDQYJKoZIhvcNAQEBBQAEggEAg7c1d6tGkEX3iNeYqsHKw8s/meTEj9DtND9Q
# 01vJCxAimeGQgjNUMU2Ji04YxqpLttdMrKQKb56TzMbOfCksz+5meK+x+wJ1AgPr
# 5GTg6dvHAAF0sOdp2dZaN1D6VA9K93Q+12TcFQnNcXdvyz2ClVR/jwou03v3pp5f
# jg1ap6UcqDNYC4SDnS04lf4Y90NmrGjGZRpiPW3uBhc2EGvJjB7hswVZAoCjr5yR
# LJQSsfcHpDSzayOOVENLrmAKOhtYXS01pGzLvPGaQ79iUXybLCLL+M0fE3+1Cyed
# iZALvwovg8QbaWyUBRlh33zZ9isXFbm/zKESLhvllrA29ZpSow==
# SIG # End signature block
