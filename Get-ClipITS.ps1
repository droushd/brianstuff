function Get-ClipITS {
    Param(
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$json,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$clip
      )
    Add-Type -AssemblyName PresentationCore
    $output = New-Object System.Collections.ArrayList($null)  #@() # An Array for the retuned objects to go into 
    [Windows.Clipboard]::GetText().Split("`n") | ForEach-Object {$output.add($PSItem)>$null}
    if ($output.count -gt 1) {
        $last = $output.count-1
        $output.removeat($last)
    }    
    $output = $output.replace("`r","").split("`t") 
    
    if ($json) {
        $output = $output | convertto-json -compress
        if ($clip){$output | clip}
        return $output
    }
    else {
        if ($clip){$output | clip}
        return $output
    }
}


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9XPe2Dv8npXR9GiqyxMmB91Q
# EaGgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUXe4tM/Q2DAvZ1sbbtmfFuRBZ
# YvswDQYJKoZIhvcNAQEBBQAEggEAVqbxdSIg6XHv5Zm96XTmyrRnxdHPxqUU3Y3Q
# otDwVQdvT7jOnL5lB72gxrp4q7JdIUAqWnohvvKrDMNMMBLx4DxJPY0RxYVdt/Av
# HEbqmZLIK2SqUGngexkYtodUgnn4Up+OitDF7ihY4+Uj73y6AcFJ8eOiVCxyZwqk
# JfqDU82TywBU77RmgDJWOKj/yxEQqrTU/NXkIEHLuEndtbNGbX0PaV0zI72zeY7l
# Zw/kYdq0Je3BgeKYXHX0d9kMCRIVWFitIGfSTQtzchp1uYIMPpD2y5vkOghVjcgb
# Y/E/eqOGgpdSS7BnFlkDJ7vRaqT8iXd9MxEmLO+3ZOwXV/n6cw==
# SIG # End signature block
