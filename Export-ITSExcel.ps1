function Export-ITSExcel {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$InputObject
    )
    Begin {
        $importexcel = get-command -module importexcel
        if ($null -eq $importexcel) {Write-Error "ImportExcel not installed";return}
        $username = get-inven -basic | foreach {$_['IntuneUPN']}
        if ($null -eq $username) {Write-Error "Username not found";return}
        $exceldata = New-Object System.Collections.ArrayList($null)
    }
    Process{
        $InputObject | ForEach-Object {$exceldata.add($PSItem) | Out-Null}
        if ($null -eq $exceldata) {Write-Error "Excel data not found";return}
    }
    End{
        Export-Excel -InputObject $exceldata -Path "C:\Users\$username\Downloads\$(Get-Date -Format 'MM-dd-yyyy-hh-mm-ss').xlsx" -TableName Default -FreezeTopRow -AutoSize
        $wasp = get-command -module wasp
        $powershell = $PSVersionTable.PSVersion -match "^5"
        if ($wasp -and $powershell) {
            $downloads = Select-UIElement | where {$_.name -match "Downloads"} |select -first 1 
            if ($downloads) {$downloads| Set-UIFocus}
            else{Start-Process "C:\Users\$username\Downloads"}    
        }
        else {
            Start-Process "C:\Users\$username\Downloads"
        }
    }
}


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5fR8cINriArivkhP3QnnTZxA
# ys2gggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU9JaVLkh67HAbwVcrxW6EUa0z
# PAkwDQYJKoZIhvcNAQEBBQAEggEAgNRpvRNjEuFdKehoQq2I7Ok/vUb/q18CL0O2
# 3U4Ok99+FzckS7fFRzfgVeMObNQBptW/7mwuuH8Qf4WeQ+G01Up//ZAqFV+sjzR6
# 7lySHnm2gkb9f2dBuCT12BkX9L4F/zMYG5d6hlKi5FB6W1Ub1OIespi+QDIIWNuq
# HITmRhKnRRt7Z3tOLtaT/4VMLn3oM/46rHUzgnhmOstFZ/xf5s+wzHqBQyc143tY
# mM9TccYXzKz7TGp7Y98zSuHs/mdfe6BlW/3VNs7EDO1JBhRcyZPgOBDhjpj/5q3V
# cJKPtbfJyuShRFHxZtcmMIUwANaQitbMTEwjZ1uKJoNBTDt/gQ==
# SIG # End signature block
