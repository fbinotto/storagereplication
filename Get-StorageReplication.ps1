# Replace with your Workspace ID
$workspaceId = "REPLACE_WITH_LA_WORKSPACE_ID"  

# Replace with your Primary Key
$SharedKey = Get-AutomationVariable -Name 'SharedKey'

# Specify the name of the record type that you'll be creating
$LogType = "StorageReplicationHealth"

# Create the function to create the authorization signature
Function Build-Signature ($workspaceId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $workspaceId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($workspaceId, $sharedKey, $body, $logType, $TimeStampField)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -workspaceId $workspaceId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $workspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process

# Connect to Azure with user-assigned managed identity
Connect-AzAccount -Identity -AccountId #REPLACE_WITH_UAMI#

$query = "Resources | where type in~ ('microsoft.storage/storageaccounts') | where sku.name contains 'G'"

$results = Search-AzGraph -Subscription $subscriptions -Query $query

foreach ($result in $results) {

	$subscriptionId = $result.SubscriptionId
	$sub = Select-AzSubscription -SubscriptionId $subscriptionId
	$storage = Get-AzStorageAccount -ResourceGroupName $result.resourceGroup -Name $result.name -IncludeGeoReplicationStats
	#$tags = $storage.Tags | ConvertTo-JSON
	# Create two records with the same set of properties to create
	$json = @"
	[{  "Storage_Name": "$($storage.StorageAccountName)",
		"Storage_LastSyncTime": "$($storage.GeoReplicationStats.LastSyncTime)",
		"Storage_Sku": "$($storage.Sku.Name)",
		"subscriptionId": "$subscriptionId",
		"subscriptionName": "$($sub.Subscription.Name)",
		"resourceId": "$($storage.id)",
		"Owner": "$($storage.Tags.Owner)"
	}]
"@
	# Submit the data to the API endpoint
	Post-LogAnalyticsData -workspaceId $workspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField "LastSyncTime"
}
