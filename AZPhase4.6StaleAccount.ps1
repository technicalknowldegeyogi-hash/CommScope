param(
    [int]$InactivityThresholdDays = 90,
    [switch]$DisableStaleAccounts,
    [switch]$ReportOnly
)

$ErrorActionPreference = 'Stop'
$script:ScriptName = $MyInvocation.MyCommand.Name
$script:Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:OutputPath = 'D:\M365\AZ PS OP'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logEntry
    if ($Level -eq 'ERROR') { Write-Error $Message }
    elseif ($Level -eq 'WARNING') { Write-Warning $Message }
    else { Write-Host $Message -ForegroundColor Gray }
}

try {
    if (-not (Test-Path $script:OutputPath)) {
        New-Item -Path $script:OutputPath -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $script:OutputPath"
    }

    $script:LogFile = Join-Path $script:OutputPath "$script:ScriptName`_$script:Timestamp.log"
    $script:CsvReport = Join-Path $script:OutputPath "StaleAccounts_$script:Timestamp.csv"

    Write-Log "Script started. Threshold: $InactivityThresholdDays days"
    Write-Log "Report only mode: $($DisableStaleAccounts -eq $false -or $ReportOnly)"
    
    $requiredScopes = @('User.Read.All', 'AuditLog.Read.All')
    if ($DisableStaleAccounts -and (-not $ReportOnly)) {
        $requiredScopes += 'User.ReadWrite.All'
    }

    Write-Log "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    Write-Log "Connected to Microsoft Graph"

    $cutoffDate = (Get-Date).AddDays(-$InactivityThresholdDays)
    Write-Log "Calculated cutoff date: $cutoffDate"

    Write-Log "Retrieving enabled users..."
    $users = Get-MgUser -Filter "accountEnabled eq true" -All `
        -Property Id, UserPrincipalName, DisplayName, AccountEnabled, `
        CreatedDateTime, SignInActivity

    Write-Log "Processing $($users.Count) enabled users..."
    $staleAccounts = @()
    $actionTaken = 'Reported'

    foreach ($user in $users) {
        $lastSignIn = $user.SignInActivity.LastSignInDateTime
        $status = 'Active'
        
        if ($null -eq $lastSignIn) {
            $status = 'Never Signed In'
            $daysInactive = [math]::Ceiling(((Get-Date) - $user.CreatedDateTime).TotalDays)
        }
        else {
            $daysInactive = [math]::Ceiling(((Get-Date) - $lastSignIn).TotalDays)
            if ($daysInactive -gt $InactivityThresholdDays) {
                $status = 'Inactive'
            }
        }

        if ($status -in @('Never Signed In', 'Inactive')) {
            $accountInfo = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName       = $user.DisplayName
                LastSignInDate    = if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }
                DaysInactive      = $daysInactive
                AccountStatus     = $status
                ActionTaken       = 'None'
                Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }

            if ($DisableStaleAccounts -and (-not $ReportOnly) -and $status -eq 'Inactive') {
                try {
                    Update-MgUser -UserId $user.Id -AccountEnabled:$false
                    $accountInfo.ActionTaken = 'Disabled'
                    $actionTaken = 'Disabled'
                    Write-Log "Disabled stale account: $($user.UserPrincipalName)" -Level 'WARNING'
                }
                catch {
                    Write-Log "Failed to disable $($user.UserPrincipalName): $_" -Level 'ERROR'
                    $accountInfo.ActionTaken = 'Error'
                }
            }

            $staleAccounts += $accountInfo
        }
    }

    if ($staleAccounts.Count -gt 0) {
        $staleAccounts | Export-Csv -Path $script:CsvReport -NoTypeInformation
        Write-Log "Exported $($staleAccounts.Count) stale accounts to: $script:CsvReport"
        
        $staleAccounts | Format-Table -Property UserPrincipalName, LastSignInDate, `
            DaysInactive, AccountStatus, ActionTaken -AutoSize | Out-Host
    }
    else {
        Write-Log "No stale accounts found meeting the $InactivityThresholdDays day threshold."
    }

    Write-Log "Script completed successfully. Action taken: $actionTaken"
}
catch {
    Write-Log "Script failed: $_" -Level 'ERROR'
    throw
}
finally {
    if (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph | Out-Null
        Write-Log "Disconnected from Microsoft Graph"
    }
}