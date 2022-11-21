
Function Get-HKEY {
  <#
  .Synopsis
  Get a registry value from the registry.

  .Description
  This function checks for a registry value: returns the value, or an error.

  .Parameter Path
  The registry Key (AKA folder)  (e.g. "HKLM:\SYSTEM\CurrentControlSet\Control\Power").

  .Parameter Name
  The registry Name (e.g. "ConsentPromptBehaviorUser")

  .Parameter CurrentUser
  If $true just get info for current user; if $false, check all users + default user

  .Example
  # Returns True if hibernation is enabled
  Get-HKEY -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "hibernateenabled" | foreach {$_ -eq 1}

  .Example
    # Returns UAC setting value 
    Get-HKEY -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\SlideShow\" -Name "DisableHardwareAcceleration"
  #>

  Param(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$Path,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$Name,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$CurrentUser,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$SpecificUser,
        # [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$values,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$subkeys,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][switch]$detailed
      )
  
    Begin {

      New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

      $checkCU = Get-Variable -Name CurrentUser
      if ($checkCU) {}
      else {$CurrentUser = $false}

      if (!$subkeys -And !$name -and !$detailed) {return "unable to process"}

      Function Get-HKEYPrivate {
        Param(
          [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$privatePath,
          [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$username
          )
        try {
          if ($detailed) {
            #this gets all values in key
            Get-Item -Path $privatePath -erroraction silentlycontinue | Select-Object -ExpandProperty Property | foreach {
                $name = $_; 
                $value = Get-Hkey -path $privatePath -name $name;
                [PSCustomObject]@{
                  Username = $username
                  Path = $privatePath
                  Name = $name
                  Value = $value
                }
            }
          }
          elseif ($subkeys) {
            #this gets all subkeys within a key 
            Get-Item -Path $privatePath -erroraction silentlycontinue | ForEach-Object {$_.GetSubKeyNames()}
          }
          else {
            # this just gets the individual value
            Get-ItemProperty -Path $privatePath -Name $Name -erroraction silentlycontinue | ForEach-Object {$_.$name}
          }
        }
        catch {Write-Error $privatePath}
      }

    }

    Process
    {
      $output = New-Object System.Collections.ArrayList($null)  #@() # An Array for the retuned objects to go into 
      if ($Path -match "HKCU:") {
          if ($CurrentUser) {
            $registryPath = $Path
            # $result = [pscustomobject]@{
            #   value = $(Get-HKEYPrivate -privatePath $registryPath)
            #   path = $registryPath
            #   username = 'currentuser'
            # }
            $result = Get-HKEYPrivate -privatePath $registryPath -username $env:USERNAME
            $output.Add($result) | Out-Null
          }
          elseif (Test-Admin) {
            if ($specificuser) {
              $ProfileList = Get-ProfileList | Where-Object {$_.sid -match $SpecificUser -or $_.username -match $SpecificUser}
            }
            else {
              $ProfileList = Get-ProfileList | Where-Object {$_.userhive -match 'C:\\Users'}# Get Username, SID, and location of ntuser.dat for all users
            }
            $Path = $Path -replace 'HKCU:',"" # this allows us to load it w diff path below
            try { # These hives are already loaded            
              $ProfileList | Where-Object {$_.userhive -notmatch 'Windows' -And $PSItem.Loaded -eq $True} | ForEach-Object {
              $registryPath = "registry::HKEY_USERS\$($PSItem.SID)$Path"
              $username = $PSItem.username
              $result = Get-HKEYPrivate -privatePath $registryPath -username $username
              $output.Add($result) | Out-Null
              Remove-Variable -Name result -ErrorAction SilentlyContinue
              } 
            }
            catch {Write-Error $registrypath}                
            # These hives are not already loaded
            $ProfileList | Where-Object {$_.userhive -notmatch 'Windows' -And $PSItem.Loaded -eq $False } | ForEach-Object {
              try {
                reg load HKU\$($PSItem.SID) $($PSItem.UserHive) | ForEach-Object {Write-Verbose $_}
                $registryPath = "registry::HKEY_USERS\$($PSItem.SID)$Path"
                $username = $PSItem.username
                $result = Get-HKEYPrivate -privatePath $registryPath -username $username
                $output.Add($result) | Out-Null
                Remove-Variable -Name result -ErrorAction SilentlyContinue
                function Out-Default {}
                [gc]::collect()
                Start-Sleep -Seconds 4
                reg unload HKU\$($PSItem.SID) | ForEach-Object {Write-Verbose $_}
                Remove-Item -Path function:Out-Default  
              }
              catch {
                function Out-Default {}
                [gc]::collect()
                Start-Sleep -Seconds 4  
                reg unload HKU\$($PSItem.SID) | ForEach-Object {Write-Verbose $_}
                Remove-Item -Path function:Out-Default  
              }
            }             
            reg load HKU\DefaultUser C:\Users\Default\ntuser.dat  | ForEach-Object {Write-Verbose $_}
            $registryPath = "registry::HKEY_USERS\DefaultUser$Path"
            $username = $PSItem.username
            $result = Get-HKEYPrivate -privatePath $registryPath -username $username
            $output.Add($result) | Out-Null
            Remove-Variable -Name result -ErrorAction SilentlyContinue
            function Out-Default {}
            [gc]::collect()
            Start-Sleep -Seconds 4
            reg unload HKU\DefaultUser  | ForEach-Object {Write-Verbose $_}
            Remove-Item -Path function:Out-Default 

          } 
          else {"error condition"}
      }
      else {
        Get-HKEYPrivate -privatePath $path
      }
  }
  End {
      Remove-PSDrive -Name HKCR | Out-Null
      
      return $output
  }
} # End Function Get-HKEY


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUc+oH5gMduZeFAuRsOkXdo1p3
# LjugggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU5vXW116sqJWl1oBs13qcxGA2
# PFUwDQYJKoZIhvcNAQEBBQAEggEAU4PDj8vyPyUNyT9fsLDbwycZDwFxB5SmsdUi
# 8ke3BAIQF4ErzP1VHp9wuSpZKeGCSNxp+gBn39PxUCUtKcBCaO70198sTit0e6Xy
# MS//DXrkyWpkvDOmsbxHb3+zIrEAyjG4Kf1mvP0+5Z7Au14/ykLLymuDqqRRckjL
# 3Q9EPmYvE/uVykT31nzZy7Ywq/V/M0BKn0C7VGukWJNu4iNBjGhkeN9KP8A3uMot
# j8LtJknuE4t6JjnJoiIymxkYW5Vzows+NLORsXpcuW/qxo7s6J+WGDTiFvNQ/X5l
# GhM5zsaND/8nNDV/3QxgHUvTbQbcKkXumS03N0LQ93Sw4uCNKQ==
# SIG # End signature block
