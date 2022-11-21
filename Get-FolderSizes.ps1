
Function Get-FolderSizes {
    <#
    .Synopsis
    Get size of a folder and subfolders 

    .Description
    This function measures the size in MB of a folder and its subfolders.  

    .Parameter Path
    The folder path  (e.g. "C:\Users").

    .Example
    # Returns data about current folder if path is not specified.
    Get-FolderSizes

    .Example
    # Returns data about specified locaiton. 
    Get-FolderSizes -Path "C:\Users" 
    #>

    Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$path
        )    
    if (!$path){$path= $pwd.path}
    $getEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $FolderSizeArray = [System.Collections.Generic.List[PSObject]]::New()

    $FolderItems = Get-ChildItem $path -force | # measure $foldername contents 
        Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -notmatch "L"} | 
        Measure-Object -property Length -sum | Select-Object Sum
    $FolderItemsOnline = Get-ChildItem $path -force | # measure $foldername contents 
        Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -match "L"} | 
        Measure-Object -property Length -sum | Select-Object Sum
    $FolderSizeArray.add([PSCustomObject]@{
        Path = $path
        MBOnDisk = "{0:N2}" -f ($FolderItems.sum / 1MB)
        MBOnline = "{0:N2}" -f ($FolderItemsOnline.sum / 1MB)
        }) | Out-Null
    Get-ChildItem $path | # measure subfolder contents 
        Where-Object {$_.PSIsContainer -eq $true} | Sort-Object | ForEach-Object {
            $subfolderpath = $PSItem.FullName
            $subFolderItems = Get-ChildItem $PSItem.FullName -recurse -force | 
            Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -notmatch "L"} | 
            Measure-Object -property Length -sum | Select-Object Sum
            $subFolderItemsOnline = Get-ChildItem $PSItem.FullName -recurse -force | 
            Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -match "L"} | 
            Measure-Object -property Length -sum | Select-Object Sum
            $FolderSizeArray.add([PSCustomObject]@{
                Path = $subfolderpath
                MBOnDisk = "{0:N2}" -f ($SubFolderItems.sum / 1MB)
                MBOnline = "{0:N2}" -f ($SubFolderItemsOnline.sum / 1MB)
            }) | Out-Null
        }
    $ErrorActionPreference = $getEAP
    return $FolderSizeArray
}
    # https://en.wikipedia.org/wiki/File_attribute


# This is the old version:
# Function Get-FolderSizes {
#     Param (
#         [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$foldername
#         )    
#     if (!$foldername){$foldername= $pwd.path}
#     $getEAP = $ErrorActionPreference
#     $ErrorActionPreference = 'SilentlyContinue'
#     $FolderItems = Get-ChildItem $foldername -force | # measure $foldername contents 
#         Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -notmatch "L"} | 
#         Measure-Object -property Length -sum | Select-Object Sum
#         $foldername + " -- " + "{0:N2}" -f ($FolderItems.sum / 1MB) + " MB"

#     Get-ChildItem $foldername | # measure subfolder contents 
#         Where-Object {$_.PSIsContainer -eq $true} | Sort-Object | foreach {
#             $subFolderItems = Get-ChildItem $PSItem.FullName -recurse -force | 
#                 Where-Object {$_.PSIsContainer -eq $false -And $_.Mode -notmatch "L"} | 
#                 Measure-Object -property Length -sum | Select-Object Sum
#             $PSItem.FullName + " -- " + "{0:N2}" -f ($subFolderItems.sum / 1MB) + " MB"
#             }
#     $ErrorActionPreference = $getEAP

# }
#     # https://en.wikipedia.org/wiki/File_attribute




# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHQGqtqOA7/s5zbikpONlLAZu
# jyugggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUQkCqzmMM5YYzpqd/3Jj7Ji2o
# VfUwDQYJKoZIhvcNAQEBBQAEggEAcw9uo9n7bqlk9EGO778pN2KNHKVEgMzgef2q
# Oe5OrgxGPsRKKbB98MO3YZbE1IU0+VH4owecbbM35rR+DVeSLbTJxQizzviXpYoe
# hthIX26O4HYvGz76xyXt1F9dCWxJaNSJbATat92nkPD/PXBXF2DF7M+Ylc+vZ1EC
# wfZFDNDgy+U8UFPuqoR0weNwrfJek0fga3+zdT++SohqCYPVzf8msttVj4zcGLWB
# /5AFPFKofAcnuSaWVtL9PyGVQGcb8ufPH0jzj2b4ZxCnXkqoLpOF/1/GJmgh62Yb
# 33cEjgm7i/hEVJdn5kTctiXixw0Ps7xIuio7NXvn5ruedsdHKg==
# SIG # End signature block
