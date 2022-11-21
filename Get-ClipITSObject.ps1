function Get-ClipITSObject {
    Add-Type -AssemblyName PresentationCore
    $output = New-Object System.Collections.ArrayList($null)  #@() # An Array for the retuned objects to go into 
    $psoutput = New-Object System.Collections.ArrayList($null)  #@() # An Array for the retuned objects to go into 
    [Windows.Clipboard]::GetText().Split("`n") | foreach {
        $row = @()
        $row = $PSItem -split "`t"    
        $output.add($row)>$null
    }
    if ($output.count -gt 1) {
        $last = $output.count-1
        $output.removeat($last)
    }    
    $properties = $output[0]
    $zbased = $properties.length
    $output.removeat(0)
    $output | foreach {
        $rc1 = New-Object PSCustomObject # if you don't recreate it each time, it's just a link so you get all the same data 
        For ($i=0; $i -lt $zbased; $i++) {
            $value = [string]$($PSItem[$i].trim().replace("`r|`n",""))
            $property = [string]$($properties[$i]).trim()
            $rc1 | Add-Member -type NoteProperty -name $property -value $value -Force
        }
        $psoutput.Add($rc1) > $null
    }
    return $psoutput
}




# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6eTbvQAHgIIn1T0UHcL8wWEN
# LfqgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUCUI15jo8rSyHWeoq9ApauUR8
# S4EwDQYJKoZIhvcNAQEBBQAEggEAiBR/8+EQZfOkkUZCk1a3tQLRfKOUEk02ZWl9
# xNkkdARafG8EgJb7IqKkLAAqelA9IzQk7w3BYTJUGzOj66wncyNd4AlrGa4zBPBG
# 4GZMsC1ZaZ+51CcBhyRNMug4+NxFzeKPeSfPowpCvHvYeokrI0/WRfTGMR9B9ePo
# Ioj+bs3Npn/l1z4hF8kpe2HUiG1LRGrWO/1a/PcrHAQu5/FEUsBlRE/AJYgHVhYD
# BiNIVWoR5yKs9kslm4HKciJfojFcAzvQg9zREoGmLfNw+lNAPAJ88QUdY/0hztdV
# mMyB1xHmTiV+OKCq+sowp+OeP8WohALhePe9KwSdZ9OLSyf2cg==
# SIG # End signature block
