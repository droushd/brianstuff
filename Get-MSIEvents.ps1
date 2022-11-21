Function Get-MSIEvents {
  <#
  .Synopsis
    Get all software install events from past X minutes.

  .Description
    This function defaults to last 30 minutes of install events and ignores and Windows Update Catalog checks.

  .Parameter Minutes
    The number of minutes to look (backwards)  (e.g. -30).

  .Example
    # Returns True if hibernation is enabled
    Get-MSIEvents
  #>

  Param(
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$Days,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$Minutes,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$az
      )
  Begin {
    $GII = Get-Command -Name Get-Inven -Module Win10ITS -ErrorAction SilentlyContinue
    # $ordered = "Z_"  
    if ($GII) {
      # Write-ITSHost "[$(Get-Date -format "H:mm:ss")] using Get-Inven"
      $private:hw = Get-Inven -basic -ordered $ordered
      # $hw['GetInven'] = $true
    }
    else {
      Write-ITSHost "[$(Get-Date -format "H:mm:ss")] no Get-Inven; exiting"
      return
    }
  }
  Process
      {
        if ($days) {$DateAfter = (Get-Date).AddDays(-$($days))}
        elseif (-not($minutes)) {$DateAfter = (Get-Date).AddMinutes(-360)}
        elseif ($minutes -gt 0) {$DateAfter = (Get-Date).AddMinutes(-$($minutes))}
        else {$DateAfter = (Get-Date).AddMinutes($minutes)}
        
        $MSIInstallers = Get-WinEvent -FilterHashtable @{StartTime=$DateAfter;logname='Application'} -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -match "msiInstaller"} |
            Where-Object {$_.message -notmatch 'Windows Installer reconfigured the product'} |
            Where-Object {$_.message -match "Product:|Product Name:|restart"} | ForEach-Object { 
              Clear-Variable -Name product -ErrorAction SilentlyContinue
              $pattern = "Product: (.*?) --"
              $product = [regex]::match($PSItem.message, $pattern).Groups[1].Value
              if ($product.length -lt 2) {
                $pattern2 = "Product Name: (.*?)\."
                $product = [regex]::match($PSItem.message, $pattern2).Groups[1].Value
              }
              Clear-Variable -name rowkey -erroraction silentlycontinue
              $rowkey = Get-Date $PSItem.timecreated -format s -erroraction silentlycontinue
              $row = [PSCustomObject]@{
                Product = $product
                InstalledOn = (Get-Date -Date $($PSItem.TimeCreated) -format s)
                Message = $PSItem.message
                RowKey = $rowkey
                PartitionKey = $env:COMPUTERNAME      
                IntuneUPN = $($hw['IntuneUPN'])
                z_ID = $PSItem.id
                z_Properties = $PSItem | Select-Object -Expand Properties | Out-String
                z_Status = $($PSItem.Properties[2].Value.replace('(NULL)',''))
                z_ReasonCode = $($PSItem.Properties[3].Value.replace('(NULL)',''))
                z_Comment = $($PSItem.Properties[5].Value.replace('(NULL)',''))
              }
              $row
            }
        
              #get-winevent -LogName Application -erroraction SilentlyContinue | where {$_.providername -match 'msiinstaller' -and $_.message -notmatch "Windows Installer reconfigured the product"} | where {[datetime]$PSItem.timecreated -gt $((Get-Date).addminutes($minutes))}  
      }
  End {
    $columns = $MSIInstallers | ForEach-Object {$Psitem.psobject.Properties}| Where-Object {$_.MemberType -match "NoteProperty"}  | ForEach-Object {$_.name} | Group-Object | ForEach-Object {$_.name}
    if (-not$az) {
      $columns_exclude = @('RowKey','PartitionKey','IntuneUPN','z_ID','z_Properties','z_Status','z_ReasonCode','z_Comment')
      $columns = $columns | Where-Object {$_ -notin $columns_exclude}
    }
    $MSIInstallers | Select-Object $columns
  }
} # End Function Get-MSIEvents




# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6WMpuj7+pfs3/6FzcmUO/fH7
# mmugggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU7W7PbOxVcio+g0YkXt6Z67oQ
# nq4wDQYJKoZIhvcNAQEBBQAEggEAabEqzicezF0ghXcv7fA283TEmxK4Ixb+XtYZ
# Tp963AX3KKyJSsspyDkC4Vh6Z+fBMM2c5tpmHPpzO3CemCfo3utw2nbw/oDMojcP
# g9GN63zchCPXqxXJhxHjfP5ynxkWJ/aVAcUM8o6ZL+P3A9K5LY1eFHL043gpOzZe
# dnxEPRh1xPBlD5/JeDx4WtFiATHBHy4Oxszq5Qd22Oq/0EWYfQqn79rBwVtpcvO3
# 39Y80TPlSqf0uDALsnaTDoqGb+7sIxVfHUUtofS2ZhxvFv8Vw7Xf7EvJQqrddK88
# Ni/AfMwdfECcgbzBYnURZbZHhnFffCWUOZDj2K+dm48hBGm4vw==
# SIG # End signature block
