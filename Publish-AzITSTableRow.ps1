function Publish-AzITSTableRow {
    <# 
        .SYNOPSIS
        Sends a hash to an Azure Log
        .DESCRIPTION 
        This function accepts a hash/dict and a table name,
        and sends it to a table in ITS All storage account. 
        Includes error handling in the table itself (not a separate error logging table)
    #>
    Param(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$logentry,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$table,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][switch]$iserror,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$isdiagnostics,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$catch,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$tableEndpoint,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$SAS,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$isfinally
      )
      Begin {
        # try {
		# 	$LAitsExists = Get-Command  -Module Win10ITS -ErrorAction SilentlyContinue | ForEach-Object {$_.name -match 'Publish-AzITSLogAnalytics'}
        # 	if ($LAitsExists) {Publish-AzITSLogAnalytics -logentry $logentry -table $table}
		# }
		# catch {Write-ITSHost "Failed: Publish-AzITSLogAnalytics";$_}
      }
      Process
      {
        # this is the storage acount URL:
        if (-not($tableEndpoint)) {$tableEndpoint = 'https://itsall.table.core.windows.net/'}
        # this provides authorization to upload: expires 2029
        if (-not($SAS)) {$SAS = "?sv=2018-03-28&ss=bfqt&srt=o&sp=wau&se=2029-05-08T02:56:43Z&st=2019-05-07T18:56:43Z&spr=https&sig=GIpgKTGgY0xDwGU%2FGVdkhj8Bd%2FY9zvDHdEDyb8e7oV0%3D"}
  
        # this section allows skipping the logging if it's called the first time during a finally statement
        if (-not($AzITSTableRow)) {$global:AzITSTableRow = 0}
        $AzITSTableRow += 1
        if ($AzITSTableRow -eq 1 -And $isfinally) {return}
  
        # get the current transcript if not specified
        if ($null -eq $isdiagnostics -And $null -ne $transcript) {
            $isdiagnostics = Get-Variable -Name Transcript | ForEach-Object {$_.value}
        }
        if ($null -ne $isdiagnostics) {
            $transcript_exists = Test-Path $isdiagnostics
        }
        else {$transcript_exists = $false}
        # $zLogEntry = $logentry | convertto-json -Depth 9
        if ($catch) {
            # Overwrite the incoming 
            if ($null -ne $($logentry['PartitionKey'])) {$PartitionKey = $logentry['PartitionKey']}
            $logentry = New-Object 'system.collections.generic.dictionary[string,string]'
            $logentry['PartitionKey'] = $PartitionKey
            # $logentry['zLogEntry'] = $($zLogEntry.tostring()).substring(1,100)
            $logentry['zException'] = $catch.Exception.message
            $logentry['zScriptStackTrace'] = $catch.scriptstacktrace   
            $callStack = Get-PSCallStack
            $logentry['zScriptLineNumber'] = $callStack.InvocationInfo.ScriptLineNumber
            # $logentry['zPSCallStack'] = $callStack | ConvertTo-Json -Depth 9            
            # try{stop-transcript|out-null} catch [System.InvalidOperationException]{}

            if ($null -ne $isdiagnostics -And $transcript_exists) {
                $logentry['zTranscript'] = Get-Content $isdiagnostics | Select-Object -last 200 | Out-String
            }
            # Write-Output "Error Condition: $($catch.scriptstacktrace)"
            # Write-Output "Error Condition: $($catch.Exception.message)"         
        }
  
        # these key fields are required: 
    #	partition keys are unique across the table; 
  
        if ($logentry.gettype().name -match 'PSCustomObject') {
            $ht2 = @{}
            $logentry.psobject.properties | & { process { 
            if($_.Value.length -lt 1){$newvalue=''}
            else{$newvalue= $_.Value}
            # this cleans variable names from asset panda: Department (User) becomes just Department
            $newname = (($_.Name) -replace('\(([^\)]+)\)', '')) -replace('\(|\)|#| ',"") 				
            $ht2[$newname] = $newvalue
            } }
            try { 
                $logentry = New-Object 'system.collections.generic.dictionary[string,string]'
                $logentry = $ht2
            }
            catch {$ht2;$_.scriptstacktrace;$_;break}
        } 
        else {
        # this is to avoid dictionary keys that start with a number (illegal char in Azure Table)
            $deletekey = @()
            $logentry.GetEnumerator() | ForEach-Object {if ($_.key -match "^[0-9]") {$deletekey += $_.key}}
            $deletekey | ForEach-Object {
                $logentry["a_$($PSItem)"]=$logentry["$PSItem"];
                $logentry.remove($PSITem) | Out-Null}
        }
        if ($null -ne $isdiagnostics -And $transcript_exists) {
            $logentry['zTranscript'] = Get-Content $isdiagnostics | Out-String
            $callStack = Get-PSCallStack
            $logentry['zScriptLineNumber'] = $callStack.InvocationInfo.ScriptLineNumber
        }
        if ($null -eq $($logentry['PartitionKey'])) {
            $PartitionKey = "$([System.Net.Dns]::GetHostName())"
            $logentry['PartitionKey'] = "$([System.Net.Dns]::GetHostName())"
        }
        else {
            $PartitionKey = $logentry['PartitionKey']
        }
        if ($null -eq $($logentry['RowKey'])) {
            $RowKey = Get-Date -Format o
            $logentry['RowKey'] = Get-Date -Format o
        }
        else {
            $RowKey = $logentry['RowKey']
        }
  
        $URI = $tableEndpoint + $table + "(PartitionKey='$PartitionKey', RowKey='$Rowkey')" + $SAS
        $RequestBody = ConvertTo-Json -InputObject $logentry -depth 9 -ErrorAction SilentlyContinue
        $EncodedRequestBody = [System.Text.Encoding]::UTF8.GetBytes($RequestBody)
        $RequestHeaders = @{
            "x-ms-date" = (Get-Date -Format r);
            "x-ms-version" = "2016-05-31";
            "Accept-Charset" = "UTF-8";
            "DataServiceVersion" = "3.0;NetFx";
            "MaxDataServiceVersion" = "3.0;NetFx";
            "Accept"    = "application/json;odata=nometadata";
            "ContentLength" = $EncodedRequestBody.Length
            }
  
        try {
            Invoke-WebRequest -Method PUT -Uri $URI -Headers $RequestHeaders -Body $EncodedRequestBody -ContentType "application/json" -UseBasicParsing #| foreach {($_.StatusCode)}
        }
        
        catch [System.Net.WebException] { 
          Write-Verbose "An exception was caught: $($_.Exception.Message)"
          $_.Exception.Response
        }
    }        
  } # End Function Publish-AzITSTableRow


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpVZh3uW9rBCUIv5v3DcSCDSs
# pPmgggNOMIIDSjCCAjKgAwIBAgIQIBPntLmZnK5B5G5IDj1xLDANBgkqhkiG9w0B
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU5d/iPeHZeLAJ03BA/J+jI6p9
# 18YwDQYJKoZIhvcNAQEBBQAEggEAgWVo1IAkm2pqmzbzvQaqFm7p1GlkIC7ALxFr
# Htv+ja6FicpC0f+ZSJLSvsJFgiISMKXP7XnRc1IXxGjUoZSmiCFhb+I7sIwaKrMw
# ijifQBFY267Ef8IzhU9NLnnMVemxsDTV1QwHvOy6VSQ/iAdE31Wsz93IYcjzq+Ir
# 4LIzTS034mEEnmybytzo8kK1uLVu96ZnZpVY3gshslXdyOXAL4n+MWztNjPXkRRt
# tIbEbhhUCDeKF9ezfQew9+gejI+Z3VTWFwOq5xWixiRk1aZdpvAnjO/rqJoHrLpo
# Ixt30Nm4XBBXuZHaEGEo2Gf5oIwsKSeDl6WdNteg7T1JnVwppw==
# SIG # End signature block
