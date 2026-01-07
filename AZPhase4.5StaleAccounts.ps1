#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.Users

param(
    [switch]$UseDeviceCode,
    [switch]$Interactive,
    [string]$TenantId,
    [string]$OutputPath = "D:\M365\AZ PS OP"
)

$ErrorActionPreference = 'Stop'
$script:FolderPath = $OutputPath
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ReportPath = Join-Path $FolderPath "PrivilegedUserChanges_$Timestamp.csv"
$script:LogPath = Join-Path $FolderPath "AccessReviewTriggers.log"
$script:BaselinePath = Join-Path $FolderPath "PrivilegedBaseline.json"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry -ForegroundColor $(if($Level -eq "ERROR"){"Red"}elseif($Level -eq "WARNING"){"Yellow"}else{"White"})
}

function Initialize-Environment {
    if (-not (Test-Path $script:FolderPath)) {
        New-Item -Path $script:FolderPath -ItemType Directory -Force | Out-Null
        Write-Log "Created directory: $script:FolderPath"
    }
}

function Connect-GraphWithScopes {
    $requiredScopes = @(
        "RoleManagement.Read.Directory",
        "GroupMember.Read.All",
        "User.Read.All",
        "Directory.Read.All"
    )
    
    try {
        $connectParams = @{
            Scopes = $requiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        if ($UseDeviceCode) {
            $connectParams.UseDeviceCode = $true
        } elseif ($Interactive) {
            $connectParams.Interactive = $true
        }
        
        Connect-MgGraph @connectParams
        Write-Log "Microsoft Graph connected successfully to tenant: $(Get-MgContext).TenantId"
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" "ERROR"
        throw
    }
}

function Get-PrivilegedRoles {
    $privilegedRoleIds = @{
        "Global Administrator" = "62e90394-69f5-4237-9190-012177145e10"
        "Security Administrator" = "194ae4cb-b126-40b2-bd5b-6091b380977d"
        "Privileged Role Administrator" = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
        "Exchange Administrator" = "29232cdf-9323-42fd-ade2-1d097af3e4de"
        "SharePoint Administrator" = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
        "User Administrator" = "fe930be7-5e62-47db-91af-98c3a49a38b1"
        "Azure AD Joined Device Local Administrator" = "9f06204d-73c1-4d4c-880a-6edb90606fd8"
        "Authentication Administrator" = "0526716b-113d-4c15-b2c8-68e3c22b9f80"
        "Intune Administrator" = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    }
    
    $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
    return $allRoles | Where-Object { $privilegedRoleIds.Values -contains $_.RoleTemplateId }
}

function Get-PrivilegedRoleMembers {
    param([array]$PrivilegedRoles)
    
    $roleMembers = @()
    foreach ($role in $PrivilegedRoles) {
        try {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user") {
                    $roleMembers += [PSCustomObject]@{
                        UserId    = $member.Id
                        UserUPN   = $member.AdditionalProperties.userPrincipalName
                        RoleName  = $role.DisplayName
                        RoleId    = $role.Id
                        Timestamp = Get-Date
                    }
                }
            }
        } catch {
            Write-Log "Error getting members for role $($role.DisplayName): $_" "WARNING"
        }
    }
    return $roleMembers
}

function Get-PrivilegedGroups {
    $privilegedKeywords = @("admin", "privileged", "elevated", "sensitive", "super", "power", "root", "breakglass")
    $allGroups = Get-MgGroup -Filter "securityEnabled eq true" -All -ErrorAction Stop
    return $allGroups | Where-Object {
        $groupName = $_.DisplayName.ToLower()
        $privilegedKeywords | Where-Object { $groupName -like "*$_*" }
    }
}

function Get-PrivilegedGroupMembers {
    param([array]$PrivilegedGroups)
    
    $groupMembers = @()
    foreach ($group in $PrivilegedGroups) {
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user") {
                    $groupMembers += [PSCustomObject]@{
                        UserId    = $member.Id
                        UserUPN   = $member.AdditionalProperties.userPrincipalName
                        GroupName = $group.DisplayName
                        GroupId   = $group.Id
                        Timestamp = Get-Date
                    }
                }
            }
        } catch {
            Write-Log "Error getting members for group $($group.DisplayName): $_" "WARNING"
        }
    }
    return $groupMembers
}

function Get-UserAccountStatus {
    param([array]$UserIds)
    
    $userStatus = @{}
    $batchSize = 20
    for ($i = 0; $i -lt $UserIds.Count; $i += $batchSize) {
        $batch = $UserIds[$i..($i + $batchSize - 1)] | Where-Object { $_ }
        try {
            $users = Get-MgUser -Filter "Id in ('$($batch -join "','")')" -Property Id, AccountEnabled, UserPrincipalName, DisplayName -All -ErrorAction Stop
            foreach ($user in $users) {
                $userStatus[$user.Id] = [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName       = $user.DisplayName
                    AccountEnabled    = $user.AccountEnabled
                    LastChecked       = Get-Date
                }
            }
        } catch {
            Write-Log "Error getting user status for batch: $_" "WARNING"
        }
    }
    return $userStatus
}

function Invoke-AccessReviewChecks {
    $results = @()
    
    Write-Log "Starting privileged user access review checks"
    
    $privilegedRoles = Get-PrivilegedRoles
    Write-Log "Found $($privilegedRoles.Count) privileged roles"
    
    $roleMembers = Get-PrivilegedRoleMembers -PrivilegedRoles $privilegedRoles
    Write-Log "Found $($roleMembers.Count) privileged role assignments"
    
    $privilegedGroups = Get-PrivilegedGroups
    Write-Log "Found $($privilegedGroups.Count) privileged groups"
    
    $groupMembers = Get-PrivilegedGroupMembers -PrivilegedGroups $privilegedGroups
    Write-Log "Found $($groupMembers.Count) privileged group memberships"
    
    $allPrivilegedUsers = ($roleMembers.UserId + $groupMembers.UserId) | Select-Object -Unique
    Write-Log "Total unique privileged users: $($allPrivilegedUsers.Count)"
    
    $userStatus = Get-UserAccountStatus -UserIds $allPrivilegedUsers
    
    foreach ($userId in $allPrivilegedUsers) {
        try {
            if ($userStatus.ContainsKey($userId)) {
                $user = $userStatus[$userId]
                $userRoles = $roleMembers | Where-Object { $_.UserId -eq $userId }
                $userGroups = $groupMembers | Where-Object { $_.UserId -eq $userId }
                
                $userRoleNames = $userRoles.RoleName -join "; "
                $userGroupNames = $userGroups.GroupName -join "; "
                
                $results += [PSCustomObject]@{
                    Timestamp            = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    UserPrincipalName    = $user.UserPrincipalName
                    DisplayName          = $user.DisplayName
                    UserId               = $userId
                    AccountEnabled       = $user.AccountEnabled
                    PrivilegedRoles      = if($userRoleNames) {$userRoleNames} else {"None"}
                    PrivilegedGroups     = if($userGroupNames) {$userGroupNames} else {"None"}
                    RoleChangeDetected   = "Baseline"
                    GroupChangeDetected  = "Baseline"
                    StatusChangeDetected = "Baseline"
                    ReviewRequired       = $false
                }
            }
        } catch {
            Write-Log "Error processing user $userId : $_" "WARNING"
        }
    }
    
    return $results
}

function Save-Baseline {
    param([array]$Results)
    
    $baseline = @{
        Timestamp = Get-Date
        Users = @{}
    }
    
    foreach ($result in $Results) {
        $baseline.Users[$result.UserId] = @{
            UserPrincipalName = $result.UserPrincipalName
            DisplayName       = $result.DisplayName
            AccountEnabled    = $result.AccountEnabled
            PrivilegedRoles   = $result.PrivilegedRoles -split "; " | Where-Object { $_ }
            PrivilegedGroups  = $result.PrivilegedGroups -split "; " | Where-Object { $_ }
        }
    }
    
    $baseline | ConvertTo-Json -Depth 10 | Out-File $script:BaselinePath -Encoding UTF8
    Write-Log "Baseline saved to $($script:BaselinePath)"
}

try {
    Write-Host "`n=== Privileged User Transfer Checks - Access Review Triggers ===" -ForegroundColor Cyan
    Write-Host "Starting execution at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    Initialize-Environment
    Connect-GraphWithScopes
    
    $reviewResults = Invoke-AccessReviewChecks
    
    if ($reviewResults.Count -gt 0) {
        $reviewResults | Export-Csv -Path $script:ReportPath -NoTypeInformation -Encoding UTF8
        Write-Log "Report generated with $($reviewResults.Count) records: $script:ReportPath"
        
        Save-Baseline -Results $reviewResults
        
        Write-Host "`n=== PRIVILEGED USERS SUMMARY ===" -ForegroundColor Green
        $reviewResults | Select-Object UserPrincipalName, DisplayName, AccountEnabled, 
            @{Name="Roles";Expression={if($_.PrivilegedRoles -ne "None"){$_.PrivilegedRoles}else{"-"}}},
            @{Name="Groups";Expression={if($_.PrivilegedGroups -ne "None"){$_.PrivilegedGroups}else{"-"}}} |
            Format-Table -AutoSize
        
        Write-Host "`n=== STATISTICS ===" -ForegroundColor Yellow
        Write-Host "Total Privileged Users: $($reviewResults.Count)" -ForegroundColor White
        Write-Host "Enabled Accounts: $(($reviewResults | Where-Object {$_.AccountEnabled -eq $true}).Count)" -ForegroundColor Green
        Write-Host "Disabled Accounts: $(($reviewResults | Where-Object {$_.AccountEnabled -eq $false}).Count)" -ForegroundColor Red
        Write-Host "Users with Admin Roles: $(($reviewResults | Where-Object {$_.PrivilegedRoles -ne 'None'}).Count)" -ForegroundColor Magenta
        Write-Host "Users in Privileged Groups: $(($reviewResults | Where-Object {$_.PrivilegedGroups -ne 'None'}).Count)" -ForegroundColor Cyan
        
    } else {
        Write-Log "No privileged users found for review"
        Write-Host "No privileged users detected in the tenant." -ForegroundColor Yellow
    }
    
    Write-Host "`nScript completed successfully at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host "Check the following files:" -ForegroundColor Gray
    Write-Host "  Report: $script:ReportPath" -ForegroundColor Gray
    Write-Host "  Log: $script:LogPath" -ForegroundColor Gray
    Write-Host "  Baseline: $script:BaselinePath" -ForegroundColor Gray
    
} catch {
    Write-Log "Script failed: $_" "ERROR"
    Write-Host "`nERROR: Script failed with error: $_" -ForegroundColor Red
    exit 1
} finally {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Microsoft Graph disconnected"
    } catch {
        # Ignore disconnect errors
    }
}