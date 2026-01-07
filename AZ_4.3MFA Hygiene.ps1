#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns

param(
    [switch]$SendEmails = $false
)

$ErrorActionPreference = "Stop"

try {
    # Connect to Microsoft Graph with required scopes
    $scopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "UserAuthenticationMethod.Read.All",
        "AuditLog.Read.All",
        "Mail.Send"
    )
    
    Connect-MgGraph -Scopes $scopes -NoWelcome
    
    $tenant = Get-MgOrganization | Select-Object -First 1
    $date = Get-Date -Format "yyyy-MM-dd"
    
    # Arrays for storing results
    $compliantUsers = @()
    $nonCompliantUsers = @()
    $notifications = @()
    
    # Define management titles and admin roles
    $managementTitles = @("*Manager*", "*Director*", "*Head*", "*Lead*")
    $adminRoles = @("Global Administrator", "Security Administrator", "Exchange Administrator")
    
    # Get all admin role members
    $adminUsers = @()
    foreach ($role in $adminRoles) {
        $roleObj = Get-MgDirectoryRole -Filter "displayName eq '$role'"
        if ($roleObj) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $roleObj.Id -All
            $adminUsers += $members.Id
        }
    }
    $adminUsers = $adminUsers | Select-Object -Unique
    
    # Get all users with pagination
    $allUsers = Get-MgUser -Filter "userType eq 'Member'" -Property "id,displayName,userPrincipalName,jobTitle,mail,accountEnabled" -All
    
    foreach ($user in $allUsers) {
        # Skip disabled accounts
        if (-not $user.AccountEnabled) { continue }
        
        $isImportantUser = $false
        $userType = "Standard"
        
        # Check for management titles
        if ($user.JobTitle) {
            foreach ($title in $managementTitles) {
                if ($user.JobTitle -like $title) {
                    $isImportantUser = $true
                    $userType = "Management"
                    break
                }
            }
        }
        
        # Check for admin roles
        if ($user.Id -in $adminUsers) {
            $isImportantUser = $true
            $userType = "Administrator"
        }
        
        # Only process important users
        if (-not $isImportantUser) { continue }
        
        # Get authentication methods
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
        
        # Determine MFA status
        $mfaConfigured = $false
        if ($authMethods) {
            $strongMethods = $authMethods | Where-Object {
                $_.AdditionalProperties."@odata.type" -in @(
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                    "#microsoft.graph.fido2AuthenticationMethod",
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
                )
            }
            $mfaConfigured = ($strongMethods.Count -gt 0)
        }
        
        # Get manager info
        $manager = Get-MgUserManager -UserId $user.Id -ErrorAction SilentlyContinue
        $managerEmail = $null
        if ($manager) {
            $managerUser = Get-MgUser -UserId $manager.Id -Property "mail" -ErrorAction SilentlyContinue
            $managerEmail = $managerUser.Mail
        }
        
        $userData = [PSCustomObject]@{
            UserId           = $user.Id
            UserPrincipalName = $user.UserPrincipalName
            DisplayName      = $user.DisplayName
            JobTitle         = $user.JobTitle
            Email            = $user.Mail
            UserType         = $userType
            MFAConfigured    = $mfaConfigured
            ManagerEmail     = $managerEmail
            LastChecked      = $date
        }
        
        if ($mfaConfigured) {
            $compliantUsers += $userData
        } else {
            $nonCompliantUsers += $userData
            
            # Check for previous notifications
            $previousNotification = $notifications | Where-Object { $_.UserId -eq $user.Id } | Sort-Object NotificationDate -Descending | Select-Object -First 1
            
            if ($SendEmails -and $user.Mail) {
                $notificationSent = $false
                $notificationType = "Initial"
                
                # Send notification
                $mailParams = @{
                    Message = @{
                        Subject = "Action Required: MFA Setup Required"
                        Body = @{
                            ContentType = "HTML"
                            Content = @"
<p>Dear $($user.DisplayName),</p>
<p>Multi-Factor Authentication (MFA) is not configured for your account. 
Please enable MFA immediately to maintain security compliance.</p>
<p>You can set up MFA at: https://aka.ms/mfasetup</p>
<p>Thank you,<br>Security Team</p>
"@
                        }
                        ToRecipients = @(@{ EmailAddress = @{ Address = $user.Mail } })
                    }
                    SaveToSentItems = $true
                }
                
                # CC manager on escalation or if no previous notification
                if ($previousNotification -and $managerEmail) {
                    $notificationType = "Escalation"
                    $mailParams.Message.CcRecipients = @(@{ EmailAddress = @{ Address = $managerEmail } })
                    $mailParams.Message.Subject = "URGENT: MFA Compliance Escalation for $($user.DisplayName)"
                } elseif ($managerEmail -and -not $previousNotification) {
                    $mailParams.Message.CcRecipients = @(@{ EmailAddress = @{ Address = $managerEmail } })
                }
                
                try {
                    Send-MgUserMail -UserId $user.Id -BodyParameter $mailParams -ErrorAction Stop
                    $notificationSent = $true
                } catch {
                    Write-Warning "Failed to send email to $($user.Mail): $_"
                }
                
                if ($notificationSent) {
                    $notification = [PSCustomObject]@{
                        UserId           = $user.Id
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName      = $user.DisplayName
                        NotificationDate = $date
                        NotificationType = $notificationType
                        RecipientEmail   = $user.Mail
                        ManagerCC        = if ($mailParams.Message.CcRecipients) { $true } else { $false }
                        ManagerEmail     = $managerEmail
                    }
                    $notifications += $notification
                }
            }
        }
    }
    
    # Export CSV files
    $compliantPath = ".\MFA_Compliant_Users_$date.csv"
    $nonCompliantPath = ".\MFA_NonCompliant_Users_$date.csv"
    $notificationsPath = ".\MFA_Notifications_$date.csv"
    
    $compliantUsers | Export-Csv -Path $compliantPath -NoTypeInformation
    $nonCompliantUsers | Export-Csv -Path $nonCompliantPath -NoTypeInformation
    
    if ($notifications.Count -gt 0) {
        $notifications | Export-Csv -Path $notificationsPath -NoTypeInformation
    } else {
        $notifications | Export-Csv -Path $notificationsPath -NoTypeInformation
    }
    
    Write-Host "`nScript completed successfully!" -ForegroundColor Green
    Write-Host "Generated files:" -ForegroundColor Yellow
    Write-Host "  $compliantPath" -ForegroundColor Cyan
    Write-Host "  $nonCompliantPath" -ForegroundColor Cyan
    if ($notifications.Count -gt 0) {
        Write-Host "  $notificationsPath" -ForegroundColor Cyan
    }
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  MFA Compliant Users: $($compliantUsers.Count)" -ForegroundColor Green
    Write-Host "  MFA Non-Compliant Users: $($nonCompliantUsers.Count)" -ForegroundColor Red
    Write-Host "  Notifications Sent: $($notifications.Count)" -ForegroundColor Cyan
    if (-not $SendEmails) {
        Write-Host "`nNote: Emails were not sent (use -SendEmails switch to enable)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Script failed: $_"
    exit 1
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}