#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups

$OutputPath = "D:\M365\AZ PS OP"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile = Join-Path $OutputPath "GroupHygiene_$Timestamp.log"

function Write-Log {
    param([string]$Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $logMessage
    $logMessage | Out-File -FilePath $LogFile -Append
}

try {
    Write-Log "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "Group.Read.All", "Directory.Read.All" -NoWelcome -ErrorAction Stop
    
    Write-Log "Retrieving groups..."
    $groups = Get-MgGroup -All -ConsistencyLevel eventual `
        -Filter "groupTypes/any(c:c eq 'unified') or securityEnabled eq true" `
        -Property "id,displayName,description,createdDateTime,mail,securityEnabled,groupTypes,mailEnabled"
    
    $results = @()
    $ownerlessGroups = @()
    $emptyGroups = @()
    
    foreach ($group in $groups) {
        Write-Log "Processing group: $($group.DisplayName)"
        
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue
            $owners = Get-MgGroupOwner -GroupId $group.Id -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue
            
            $memberCount = if ($members) { $members.Count } else { 0 }
            $ownerCount = if ($owners) { $owners.Count } else { 0 }
            
            $result = [PSCustomObject]@{
                GroupId = $group.Id
                DisplayName = $group.DisplayName
                Description = $group.Description
                Email = $group.Mail
                GroupType = if ($group.GroupTypes -contains "Unified") { "Microsoft 365" } else { "Security" }
                CreatedDate = $group.CreatedDateTime
                MemberCount = $memberCount
                OwnerCount = $ownerCount
                IsEmpty = ($memberCount -eq 0)
                IsOwnerless = ($ownerCount -eq 0)
                Status = if ($ownerCount -eq 0) { "Ownerless" } elseif ($memberCount -eq 0) { "Empty" } else { "Healthy" }
            }
            
            $results += $result
            
            if ($result.IsOwnerless) {
                $ownerlessGroups += $result
                Write-Log "  WARNING: Group has no owners"
            }
            
            if ($result.IsEmpty) {
                $emptyGroups += $result
                Write-Log "  WARNING: Group has no members"
            }
        }
        catch {
            Write-Log "  ERROR: Failed to retrieve details for group: $($_.Exception.Message)"
        }
    }
    
    $allGroupsFile = Join-Path $OutputPath "AllGroups_$Timestamp.csv"
    $results | Export-Csv -Path $allGroupsFile -NoTypeInformation -Encoding UTF8
    
    if ($ownerlessGroups.Count -gt 0) {
        $ownerlessFile = Join-Path $OutputPath "OwnerlessGroups_$Timestamp.csv"
        $ownerlessGroups | Export-Csv -Path $ownerlessFile -NoTypeInformation -Encoding UTF8
    }
    
    if ($emptyGroups.Count -gt 0) {
        $emptyFile = Join-Path $OutputPath "EmptyGroups_$Timestamp.csv"
        $emptyGroups | Export-Csv -Path $emptyFile -NoTypeInformation -Encoding UTF8
    }
    
    Write-Host "`n" + ("="*60)
    Write-Host "GROUP HYGIENE REPORT SUMMARY" -ForegroundColor Cyan
    Write-Host "="*60
    Write-Host "Total Groups Processed: $($results.Count)" -ForegroundColor White
    Write-Host "Ownerless Groups: $($ownerlessGroups.Count)" -ForegroundColor Yellow
    Write-Host "Empty Groups: $($emptyGroups.Count)" -ForegroundColor Yellow
    Write-Host "Healthy Groups: $(($results | Where-Object { $_.Status -eq 'Healthy' }).Count)" -ForegroundColor Green
    
    Write-Host "`nFiles Created:" -ForegroundColor Cyan
    Write-Host "  • Log: $LogFile"
    Write-Host "  • All Groups: $allGroupsFile"
    if ($ownerlessGroups.Count -gt 0) { Write-Host "  • Ownerless Groups: $ownerlessFile" }
    if ($emptyGroups.Count -gt 0) { Write-Host "  • Empty Groups: $emptyFile" }
    Write-Host "`nScript completed successfully!" -ForegroundColor Green
    
}
catch {
    Write-Host "`nCRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script terminated." -ForegroundColor Red
    exit 1
}