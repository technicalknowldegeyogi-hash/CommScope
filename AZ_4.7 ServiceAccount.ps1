#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns

param(
    [string]$OutputPath = "D:\M365\AZ PS OP"
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path -Path $OutputPath -ChildPath "ServiceAccountRegister_Log_$timestamp.txt"
$csvFile = Join-Path -Path $OutputPath -ChildPath "ServiceAccountRegister_$timestamp.csv"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage
}

try {
    # Create output directory if missing
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Created output directory: $OutputPath"
    }

    Write-Log "Script execution started"

    # Connect to Microsoft Graph with minimal required scopes
    $requiredScopes = @(
        "User.Read.All",
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All"
    )
    
    $graphContext = Get-MgContext
    if (-not $graphContext -or $graphContext.Account -eq $null) {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        Write-Log "Connected to Microsoft Graph"
    } else {
        Write-Log "Already connected to Microsoft Graph"
    }

    # Initialize collection array
    $serviceAccounts = @()

    # 1. Identify potential service user accounts (based on naming patterns and non-interactive indicators)
    Write-Log "Scanning user accounts..."
    $allUsers = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime, UserType, Mail
    
    $servicePatterns = @("*svc*", "*service*", "*sa*", "*app*", "*api*", "*automation*", "*integration*", "*system*", "*bot*")
    
    foreach ($user in $allUsers) {
        $isPotentialServiceAccount = $false
        
        # Check naming patterns
        foreach ($pattern in $servicePatterns) {
            if ($user.UserPrincipalName -like $pattern -or $user.DisplayName -like $pattern) {
                $isPotentialServiceAccount = $true
                break
            }
        }
        
        # Check for non-interactive indicators (service accounts often lack mail)
        if ($isPotentialServiceAccount -or [string]::IsNullOrEmpty($user.Mail)) {
            try {
                # Get user sign-in activity
                $signIns = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1 -ErrorAction SilentlyContinue
                $lastSignIn = if ($signIns) { $signIns[0].CreatedDateTime } else { $null }
                
                # Get directory roles
                $roles = Get-MgUserMemberOf -UserId $user.Id -All | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole' }
                $roleNames = $roles | ForEach-Object { $_.AdditionalProperties['displayName'] }
                
                $serviceAccounts += [PSCustomObject]@{
                    Name                  = $user.DisplayName
                    ObjectId              = $user.Id
                    AccountType           = "User"
                    UserPrincipalName     = $user.UserPrincipalName
                    CreatedDate           = $user.CreatedDateTime
                    AccountEnabled        = $user.AccountEnabled
                    Owners                = $null  # User accounts don't have direct owners
                    AssignedRoles         = ($roleNames -join "; ")
                    LastSignInActivity    = $lastSignIn
                    RequiresReview        = if ($lastSignIn -lt (Get-Date).AddDays(-90)) { $true } else { $false }
                    ReviewNotes           = if ($lastSignIn -lt (Get-Date).AddDays(-90)) { "No sign-in activity in last 90 days" } else { "" }
                }
            } catch {
                Write-Log "Error processing user $($user.DisplayName): $_" -Level "WARNING"
            }
        }
    }

    # 2. Identify application registrations
    Write-Log "Scanning application registrations..."
    $allApps = Get-MgApplication -All -Property Id, DisplayName, AppId, CreatedDateTime, PublisherDomain, SignInAudience
    
    foreach ($app in $allApps) {
        try {
            # Get app owners
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
            $ownerNames = $owners | ForEach-Object { 
                if ($_.AdditionalProperties['userPrincipalName']) { 
                    $_.AdditionalProperties['userPrincipalName'] 
                } elseif ($_.AdditionalProperties['displayName']) {
                    $_.AdditionalProperties['displayName']
                }
            }
            
            # Get app permissions
            $permissions = @()
            if ($app.RequiredResourceAccess) {
                foreach ($resource in $app.RequiredResourceAccess) {
                    $permissions += "$($resource.ResourceAppId) - $($resource.ResourceAccess.Id -join ', ')"
                }
            }
            
            $serviceAccounts += [PSCustomObject]@{
                Name                  = $app.DisplayName
                ObjectId              = $app.Id
                AccountType           = "Application Registration"
                UserPrincipalName     = $app.AppId
                CreatedDate           = $app.CreatedDateTime
                AccountEnabled        = $true
                Owners                = ($ownerNames -join "; ")
                AssignedRoles         = ($permissions -join " | ")
                LastSignInActivity    = $null  # Not available at app registration level
                RequiresReview        = $true  # Always flag for review
                ReviewNotes           = "Application registration requires periodic permission review"
            }
        } catch {
            Write-Log "Error processing application $($app.DisplayName): $_" -Level "WARNING"
        }
    }

    # 3. Identify service principals (enterprise applications)
    Write-Log "Scanning service principals..."
    $allServicePrincipals = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, CreatedDateTime, AppDisplayName, ServicePrincipalType
    
    foreach ($sp in $allServicePrincipals) {
        try {
            # Get service principal owners
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
            $ownerNames = $owners | ForEach-Object { 
                if ($_.AdditionalProperties['userPrincipalName']) { 
                    $_.AdditionalProperties['userPrincipalName'] 
                } elseif ($_.AdditionalProperties['displayName']) {
                    $_.AdditionalProperties['displayName']
                }
            }
            
            # Get app role assignments
            $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
            $roleAssignments = $appRoles | ForEach-Object { 
                "$($_.PrincipalDisplayName) -> $($_.AppRoleId)" 
            }
            
            $serviceAccounts += [PSCustomObject]@{
                Name                  = $sp.DisplayName
                ObjectId              = $sp.Id
                AccountType           = "Service Principal"
                UserPrincipalName     = $sp.AppId
                CreatedDate           = $sp.CreatedDateTime
                AccountEnabled        = $true
                Owners                = ($ownerNames -join "; ")
                AssignedRoles         = ($roleAssignments -join "; ")
                LastSignInActivity    = $null  # Requires Azure AD Premium for sign-in logs
                RequiresReview        = if ($sp.CreatedDateTime -lt (Get-Date).AddDays(-180)) { $true } else { $false }
                ReviewNotes           = if ($sp.CreatedDateTime -lt (Get-Date).AddDays(-180)) { "Created more than 180 days ago" } else { "" }
            }
        } catch {
            Write-Log "Error processing service principal $($sp.DisplayName): $_" -Level "WARNING"
        }
    }

    # Export to CSV
    if ($serviceAccounts.Count -gt 0) {
        $serviceAccounts | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($serviceAccounts.Count) service accounts to $csvFile"
        
        # Summary report
        $reviewCount = ($serviceAccounts | Where-Object { $_.RequiresReview -eq $true }).Count
        Write-Log "Summary: $($serviceAccounts.Count) total service accounts identified. $reviewCount require review."
        
        # Output to console for immediate visibility
        Write-Host "`nService Account Inventory Complete" -ForegroundColor Green
        Write-Host "Total accounts identified: $($serviceAccounts.Count)" -ForegroundColor Yellow
        Write-Host "Accounts requiring review: $reviewCount" -ForegroundColor Cyan
        Write-Host "CSV file: $csvFile" -ForegroundColor White
        Write-Host "Log file: $logFile" -ForegroundColor White
        
    } else {
        Write-Log "No service accounts found" -Level "WARNING"
        Write-Host "No service accounts found in the tenant." -ForegroundColor Yellow
    }

} catch {
    $errorMessage = "Script failed: $($_.Exception.Message)"
    Write-Log $errorMessage -Level "ERROR"
    Write-Error $errorMessage
    exit 1
} finally {
    Write-Log "Script execution completed"
}