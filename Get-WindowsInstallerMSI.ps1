Function Get-WindowsInstallerMSI {
    Param (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, HelpMessage = "MSI Database Properties", ValueFromPipeline = $true)][switch]$properties
    )
    [System.Collections.ArrayList]$returnlist = @()
    Get-ChildItem C:\Windows\Installer\*.msi -ErrorAction SilentlyContinue | ForEach-Object {
      $fullname = $_.FullName
      Get-AuthenticodeSignature -FilePath $_.fullname -ErrorAction SilentlyContinue | Select-Object -expand signercertificate | ForEach-Object {
          $rc1 = [PSCustomObject]@{
              FullName = $fullname
              Subject = $_.subject
          }
          $returnlist.add($rc1) | Out-Null
      }
    }
    if ($properties) {
        $private:propertieslist = New-Object System.Collections.ArrayList($null)  #New-Object PSCustomObject
        $returnlist | foreach {
            $Value = Get-MSIProperties $_
            $propertieslist.add($value) | Out-Null
        }
        return $propertieslist
    }
    else {
        return $returnlist
    }            
          
}


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUB8AB5xaZr5CmixqeOX9jbgzl
# HAigggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU2wdRIHTHmqFe6cwfZFDG+xOd
# IpowDQYJKoZIhvcNAQEBBQAEggEAkK9IVqqJj6qz6xfBy9zHVCy8GNb0hLHyCzAc
# cxw67t7Pbc2yCZ2AHE3zCfNMYZjvqIlHyC7SNmdho+cPFr1UbXgoo7D8LBpAJMDC
# 9WGefhegrqSJlcjRW3EXmfuY6MnHMjEERg30ODUMTVyHXRZv38otccSme7LZVSP7
# 1Ufjzud2+BiO4GXde0cMaTdHxb3YqqrS1iTq2BDd0BKsPcjwKS5uKRpaIhUK0N0h
# FcyloiC7yM2MlRh/zVopMnWT+laSF/7bWIkCzzuaSWKZe+4LhTyXpNYgoLzs7clp
# rgu2y27WTAH2SDbdIcep/AxbexSiK6e1hn428m/0pcQXREr8og==
# SIG # End signature block
