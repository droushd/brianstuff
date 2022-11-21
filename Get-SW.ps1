Function Get-SW {
  <#
  .Synopsis
    Get 32 and 64 bit software installed by polling Registry keys.

  .Description
  Parses uninstall strings for easier use.  Returns a PSCustomObject.  

  .Example
    # Get Adobe Acrobat Reader information
    $sw | Where-Object {$_.Publisher -match "Adobe" -And $_.displayname -match "Reader"}   
  #>
  function parseUninstallString( [string]$proguninstallstring, [string]$uninstallstringmatchstring ) {
    # credit: https://github.com/arcadesdude/BRU/blob/master/Bloatware-Removal-Utility.ps1
    # parseUninstallString takes the uninstallstring, and the uninstallstringmatchstring then
    # then returns the path and the arguments seperately in a form that Start-Process can use
        # Reset $uninstallarguments and $matches each loop iteration
        $uninstallpath = $proguninstallstring
        $uninstallarguments = $null
        Clear-Variable -Name matches -Force -ErrorAction SilentlyContinue

        $uninstallpath = $uninstallpath -replace "^cmd \/c", ""
        $uninstallpath = $uninstallpath -replace "^RunDll32.*LaunchSetup\ ", ""
        $uninstallpath = $uninstallpath.TrimStart(" ").TrimEnd(" ")
        $uninstallpath -match $uninstallstringmatchstring | Out-Null

        if ($matches) { # only matches if arguments exist
            $uninstallpath = $matches[1]
            $uninstallarguments = $matches[2]
        }

        #remove spaces, single and double quotes from the process path and aurgument list at the begining and end of each
        $uninstallpath = $uninstallpath.TrimStart("`"`' " ).TrimEnd("`"`' " )
        if ($null -ne $uninstallarguments) {
            $uninstallarguments = $uninstallarguments.TrimStart("`"`' " ).TrimEnd("`"`' " )
        }

        $uninstallpath = "`""+$uninstallpath+"`""
        $returned = @($uninstallpath,$uninstallarguments)
        return $returned

    } # end function parseUninstallString( $proguninstallstring, $uninstallstringmatchstring)

  $global:uninstallstringmatchstring = "^(.*?)((\ +?[\/\-_].*)|([`"`']\ +?.*))$"

  $sw_32BitApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* #| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
  $sw_32BitApps | ForEach-Object {
    if ($PSItem.QuietUninstallString) {$proguninstallstring = $PSItem.QuietUninstallString}
    else {
        $proguninstallstring = $PSItem.UninstallString
        $extraargs =" /qn REBOOT=REALLYSUPRESS"
        }
    $returned = parseUninstallString $proguninstallstring $uninstallstringmatchstring
    $uninstallpath = ($returned[0]).trim()
    $uninstallArguments = "$($returned[1]) $extraargs".trim() 
    Add-Member -inputobject $_ -type NoteProperty -name itsUninstallPath -Value $uninstallPath
    Add-Member -inputobject $_ -type NoteProperty -name itsUninstallArguments -Value $uninstallArguments
    Add-Member -inputobject $_ -type NoteProperty -name bit -Value '32'
  } 
  $sw_64BitApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* #| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
  $sw_64BitApps | ForEach-Object {
    if ($PSItem.QuietUninstallString) {$proguninstallstring = $PSItem.QuietUninstallString}
    else {
        $proguninstallstring = $PSItem.UninstallString
        $extraargs =" /qn REBOOT=REALLYSUPRESS"
        }
    $returned = parseUninstallString $proguninstallstring $uninstallstringmatchstring
    $uninstallpath = ($returned[0]).trim()
    $uninstallArguments = "$($returned[1]) $extraargs".trim() 
    Add-Member -inputobject $_ -type NoteProperty -name itsUninstallPath -Value $uninstallPath
    Add-Member -inputobject $_ -type NoteProperty -name itsUninstallArguments -Value $uninstallArguments
    Add-Member -inputobject $_ -type NoteProperty -name bit -Value '64'
  } 


#   function Get-InstalledApplications() {
#     param(
#         [string]$UserSid
#     )
    
#     New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
#     $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")

#     Get-HKEY -specificuser 'droush' -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -subkeys | foreach {
#       $subkey = $PSItem
#       Get-HKEY -specificuser 'droush' -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$subkey" -values 
#     }
#     $regpath += "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 
#     }
#     $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
#     $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName   
#     Remove-PSDrive -Name "HKU" | Out-Null
#     Return $Apps
# }


  $sw = @() #New-Object System.Collections.ArrayList($null)  #New-Object PSCustomObject
  $sw = $sw_32BitApps + $sw_64BitApps 
  # $sw | foreach {
  #   if ($PSItem.QuietUninstallString) {$proguninstallstring = $PSItem.QuietUninstallString}
  #   else {
  #       $proguninstallstring = $PSItem.UninstallString
  #       $extraargs =" /qn REBOOT=REALLYSUPRESS"
  #       }
  #   $returned = parseUninstallString $proguninstallstring $uninstallstringmatchstring
  #   $uninstallpath = ($returned[0]).trim()
  #   $uninstallArguments = "$($returned[1]) $extraargs".trim() 
  #   $PSItem | Add-Member -type NoteProperty -name itsUninstallPath -Value $uninstallPath -Force
  #   $PSItem | Add-Member -type NoteProperty -name itsUninstallArguments -Value $uninstallArguments -Force
  # }
  return $sw
} # End Function Get-SW



# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYLl9dU06CQpFEDUP/8vcW8gv
# 7zigggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUepJD4Cdl6X1aLhnai7yGYfMw
# 7OswDQYJKoZIhvcNAQEBBQAEggEAS+V3Cd0KgVrU/lCNWePM6fUByxY0/Xrkvrid
# fIRZIBu9IZsVEzvCRDdN6jbvQ+/zx/LmBLMwroUz3RFMliuGBFx9hWSP4qN+nK8v
# ev/YpSCyJJyN/nEve6xo6dqq5AnY9kKyVmYe2084pr9WYjIZ01KITWLC31aghLAE
# ItqF+EGnAaA+cucqS1MjWeWiXcJ+S2xPAyZi1Uw+3lUm9n8rw9ogaliRonf8yeah
# zCa0d3VP+o6EgEcplonxwjueo3ohxw1nh/nPZSLMUKC43i6nAsGTbff4EwkrQzlG
# UNzI8GmI0qNC785S8g8UF5Ghudgg8w+zwHS927IlDQAKtpNqrw==
# SIG # End signature block
