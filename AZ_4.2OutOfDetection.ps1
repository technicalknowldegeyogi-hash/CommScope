$RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.All",
    "User.Read.All"
)

Connect-MgGraph -Scopes $RequiredScopes -NoWelcome

$CurrentDate = Get-Date
$Yesterday = $CurrentDate.AddDays(-1)
$OutputPath = "D:\M365\AZ PS OP"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force
}

$LogFile = Join-Path $OutputPath "OutOfProcessDetection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path $LogFile -Append

try {
    Write-Host "Querying security-related audit logs..." -ForegroundColor Green
    
    $SuspiciousEvents = @()
    $PrivilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator", "SharePoint Administrator")
    
    $AuditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($Yesterday.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    
    foreach ($Log in $AuditLogs) {
        $Activity = $Log.ActivityDisplayName
        $InitiatedBy = $Log.InitiatedBy.User.UserPrincipalName
        $AppDisplayName = $Log.InitiatedBy.App.DisplayName
        
        $IsSuspicious = $false
        $Reason = ""
        
        switch -Wildcard ($Activity) {
            "*role*" {
                if ($Activity -eq "Add member to role" -or $Activity -eq "Update role") {
                    $TargetRole = ($Log.TargetResources | Where-Object { $_.ResourceType -eq "Role" }).DisplayName
                    if ($TargetRole -in $PrivilegedRoles -and $AppDisplayName -ne "Privileged Identity Management") {
                        $IsSuspicious = $true
                        $Reason = "Privileged role assignment outside PIM"
                    }
                }
            }
            
            "*conditional*" {
                $IsSuspicious = $true
                $Reason = "Conditional Access policy modified"
            }
            
            "*MFA*" {
                $IsSuspicious = $true
                $Reason = "MFA settings modified"
            }
            
            "*security*default*" {
                $IsSuspicious = $true
                $Reason = "Security defaults modified"
            }
            
            "*authentication*" {
                if ($Activity -match "authentication method" -or $Activity -match "password") {
                    $IsSuspicious = $true
                    $Reason = "Authentication settings modified"
                }
            }
        }
        
        if ($IsSuspicious) {
            $SuspiciousEvent = [PSCustomObject]@{
                Timestamp = $Log.ActivityDateTime
                Activity = $Activity
                InitiatedByUser = $InitiatedBy
                InitiatedByApp = $AppDisplayName
                Category = $Log.Category
                Reason = $Reason
                IPAddress = $Log.LoggedByService
                Target = ($Log.TargetResources | Select-Object -First 1).DisplayName
                AdditionalDetails = $Log.AdditionalDetails
            }
            $SuspiciousEvents += $SuspiciousEvent
        }
    }
    
    Write-Host "Querying directory role assignments..." -ForegroundColor Green
    
    $Roles = Get-MgDirectoryRole -All
    $RecentRoleAssignments = @()
    
    foreach ($Role in $Roles) {
        if ($Role.DisplayName -in $PrivilegedRoles) {
            $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All
            
            foreach ($Member in $Members) {
                $MemberDetails = Get-MgUser -UserId $Member.Id -ErrorAction SilentlyContinue
                if ($MemberDetails) {
                    $RoleAssignment = [PSCustomObject]@{
                        RoleName = $Role.DisplayName
                        MemberUPN = $MemberDetails.UserPrincipalName
                        MemberDisplayName = $MemberDetails.DisplayName
                        MemberId = $MemberDetails.Id
                        AccountEnabled = $MemberDetails.AccountEnabled
                        CreatedDate = $MemberDetails.CreatedDateTime
                        LastPasswordChange = $MemberDetails.LastPasswordChangeDateTime
                    }
                    $RecentRoleAssignments += $RoleAssignment
                }
            }
        }
    }
    
    $RecentRoleAssignments | Export-Csv -Path (Join-Path $OutputPath "RecentRoleAssignments.csv") -NoTypeInformation
    
    if ($SuspiciousEvents.Count -gt 0) {
        $SuspiciousEvents | Export-Csv -Path (Join-Path $OutputPath "SuspiciousEvents_Detected.csv") -NoTypeInformation
        
        Write-Host "`n[ALERT] Detected $($SuspiciousEvents.Count) suspicious events:" -ForegroundColor Red
        foreach ($Event in $SuspiciousEvents | Select-Object -First 10) {
            Write-Host "  - $($Event.Timestamp): $($Event.Activity) by $($Event.InitiatedByUser) ($($Event.Reason))" -ForegroundColor Yellow
        }
        
        if ($SuspiciousEvents.Count -gt 10) {
            Write-Host "  ... and $($SuspiciousEvents.Count - 10) more events" -ForegroundColor Yellow
        }
    } else {
        [PSCustomObject]@{
            Status = "No suspicious events detected"
            ScanTime = Get-Date
            ScanWindow = "Last 24 hours"
        } | Export-Csv -Path (Join-Path $OutputPath "SuspiciousEvents_Detected.csv") -NoTypeInformation
        
        Write-Host "No suspicious events detected in the last 24 hours" -ForegroundColor Green
    }
    
    Write-Host "`nScript completed successfully!" -ForegroundColor Green
    Write-Host "Output location: $OutputPath" -ForegroundColor Cyan
    Write-Host "Files created:" -ForegroundColor Cyan
    Write-Host "  - $(Split-Path $LogFile -Leaf)" -ForegroundColor Cyan
    Write-Host "  - RecentRoleAssignments.csv" -ForegroundColor Cyan
    Write-Host "  - SuspiciousEvents_Detected.csv" -ForegroundColor Cyan
    
} catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
}

Stop-Transcript
Disconnect-MgGraph