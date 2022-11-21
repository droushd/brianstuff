Function Find-InTemp {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$filename
        )    
    $files = New-Object System.Collections.ArrayList($null)  #@() # An Array for the retuned objects to go into 

    Get-ChildItem C:\Windows\Temp\*.* | Where-Object {$_.name -match $filename} | ForEach-Object {$files.add($_) | Out-Null }
    Get-ChildItem C:\Users\*\AppData\Local\Temp\*.* | Where-Object {$_.name -match $filename} | ForEach-Object {$files.add($_) | Out-Null }
    return $files
}




# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDROrPyGoWfoSY4NYOuf7bMh3
# ckygggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUIqmP5CF0+PE/F8HiDLDi+dCN
# Ts8wDQYJKoZIhvcNAQEBBQAEggEAOBnoiQxs8ox9AHwWf+efAUWQUPOd+uN0bckO
# 8a9ChL7RRumumpRyinDNxIosPfm/DL//TeltH9mVuQbliyHGFJ8kZarfGAzSByjG
# 6jZPc03XfOrD46ME4VVBwZN0QDn08uJaMVt5s+pa3CEiEvy52eUpd5uHzaB6WRHk
# 7E105xERcCwXzzMIBo7yOmBTIIZ4/AD7bdRw+y6QufDV77sSZte5nnznIuqyZmMd
# PkSUt+iICZaFeUv+Lo3a8N/qKwIbqO/yDty9BlV/qeZKZrQ/0OLbzuJVXFE6tKYA
# rnPnohr3HLpsew49ycKobYUjzEBzpHsKFb0C3Q2NMgdZ5A+52Q==
# SIG # End signature block
