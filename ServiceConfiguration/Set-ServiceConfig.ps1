function ConvertTo-Boolean {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$Value
    )
    if ($Value -is [bool]) {
        return $Value
    }
    return [System.Convert]::ToBoolean($Value)
}

function ConvertTo-TimeSpan {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$Value
    )
    if ($Value -is [System.TimeSpan]) {
        return $Value
    }
    return [System.TimeSpan]::Parse($Value)
}

function Set-ServiceConfig {
    param ([string]$ConfigPath)

    $Config = ConvertFrom-Yaml (Get-Content -Raw -Path $ConfigPath)

    $adminRoles = @("Organization Management", "Global Administrator")
    $adminUsers = @()

    foreach ($role in $adminRoles) {
        try {
            $roleMembers = Get-RoleGroupMember -Identity $role
            $adminUsers += $roleMembers | Select-Object -ExpandProperty PrimarySmtpAddress
        }
        catch [Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException] {
            Log-Message "Role group '$role' not found. Skipping..." "WARNING"
        }
        catch {
            Log-Message "An error occurred while retrieving members for role '$role': $_" "ERROR"
        }
    }

    $adminUsers = $adminUsers | Sort-Object -Unique

    # Log the admin users
    if ($adminUsers.Count -gt 0) {
        Log-Message "Logging the list of admin users retrieved..." "INFO"
        foreach ($adminUser in $adminUsers) {
            Log-Message "Admin User: $adminUser" "INFO"
        }
    }
    else {
        Log-Message "No admin users were found." "ERROR"
    }


    $tasks = @(
        @{ Name = "Enable Organization Customization"; Action = { 
                $orgCustomization = Get-OrganizationConfig
                if ($orgCustomization.IsMultiGeoConfigurationEnabled -eq $false) {
                    Enable-OrganizationCustomization
                    Log-Message "Organization Customization enabled successfully." "SUCCESS"
                }
                else {
                    Log-Message "Organization Customization is already enabled." "INFO"
                }
            } 
        },
        @{ Name = "Enable AIP Service"; Action = { 
                $aipServiceStatus = Get-AipService
                if ($aipServiceStatus.IsEnabled -eq $false) {
                    Enable-AipService
                    Log-Message "AIP Service enabled successfully." "SUCCESS"
                }
                else {
                    Log-Message "AIP Service is already enabled." "INFO"
                }
            } 
        },        
        @{ Name = "Enable Send-from-Alias"; Action = { 
                Set-OrganizationConfig -SendFromAliasEnabled (ConvertTo-Boolean $Config.Exchange.SendFromAlias) 
            } 
        },
        @{ Name = "Disable Focused Inbox"; Action = { 
                Set-OrganizationConfig -FocusedInboxOn (ConvertTo-Boolean $Config.Exchange.FocusedInbox) 
            } 
        },
        @{ Name = "Enable Distribution List Naming Policy"; Action = { 
                Set-OrganizationConfig -DistributionGroupNamingPolicy $Config.Exchange.DistributionGroupNamingPolicy 
            } 
        },
        @{ Name = "Enable Plus Addressing"; Action = { 
                Set-OrganizationConfig -DisablePlusAddressInRecipients (ConvertTo-Boolean $Config.Exchange.PlusAddressing) 
            } 
        },
        @{ Name = "Configure Mail-Tips"; Action = { 
                Set-OrganizationConfig -MailTipsAllTipsEnabled (ConvertTo-Boolean $Config.Exchange.MailTipsAllTipsEnabled) `
                    -MailTipsExternalRecipientsTipsEnabled (ConvertTo-Boolean $Config.Exchange.MailTipsExternalRecipientsTipsEnabled) `
                    -MailTipsGroupMetricsEnabled (ConvertTo-Boolean $Config.Exchange.MailTipsGroupMetricsEnabled) `
                    -MailTipsMailboxSourcedTipsEnabled (ConvertTo-Boolean $Config.Exchange.MailTipsMailboxSourcedTipsEnabled) `
                    -MailTipsLargeAudienceThreshold $Config.Exchange.MailTipsLargeAudienceThreshold
            } 
        },
        @{ Name = "Enable Read Tracking"; Action = { 
                Set-OrganizationConfig -ReadTrackingEnabled (ConvertTo-Boolean $Config.Exchange.ReadTracking) 
            } 
        },
        @{ Name = "Enable Public Computer Detection"; Action = { 
                Set-OrganizationConfig -PublicComputersDetectionEnabled (ConvertTo-Boolean $Config.Exchange.PublicComputerDetection) 
            } 
        },
        @{ Name = "Disable Outlook Pay"; Action = { 
                Set-OrganizationConfig -OutlookPayEnabled (ConvertTo-Boolean $Config.Exchange.OutlookPay) 
            } 
        },
        @{ Name = "Enable Lean Pop-Outs for OWA"; Action = { 
                Set-OrganizationConfig -LeanPopoutEnabled (ConvertTo-Boolean $Config.Exchange.LeanPopout) 
            } 
        },
        @{ Name = "Enable Outlook Events Recognition"; Action = { 
                Set-OrganizationConfig -EnableOutlookEvents (ConvertTo-Boolean $Config.Exchange.OutlookEventsRecognition); 
                Set-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' -LocalEventsEnabled (ConvertTo-Boolean $Config.Exchange.LocalEventsEnabled) 
            } 
        },
        @{ Name = "Disable Feedback in Outlook Online"; Action = { 
                Set-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' -FeedbackEnabled (ConvertTo-Boolean $Config.Exchange.FeedbackEnabled) `
                    -UserVoiceEnabled (ConvertTo-Boolean $Config.Exchange.UserVoiceEnabled)
            } 
        },
        @{ Name = "Enable Modern Authentication"; Action = { 
                Set-OrganizationConfig -OAuth2ClientProfileEnabled (ConvertTo-Boolean $Config.Exchange.ModernAuthentication) 
            } 
        },
        @{ Name = "Block Consumer Storage in OWA"; Action = { 
                Set-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' -AdditionalStorageProvidersAvailable (ConvertTo-Boolean $Config.Exchange.BlockConsumerStorageOWA) 
            } 
        },
        @{ Name = "Block Attachment Download on Unmanaged Devices in OWA"; Action = { 
                Set-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' -ConditionalAccessPolicy $Config.Exchange.ConditionalAccessPolicy 
            } 
        },
        @{ Name = "Set Retention Limit on Deleted Items"; Action = { 
                $retentionDays = $Config.Exchange.RetentionLimitDeletedItems
                if (-not (Get-RetentionPolicyTag -Identity "Deleted Items $retentionDays Days" -ErrorAction SilentlyContinue)) {
                    New-RetentionPolicyTag -Name "Deleted Items $retentionDays Days" -RetentionAction PermanentlyDelete -AgeLimitForRetention $retentionDays -Type DeletedItems
                    Log-Message "Retention policy tag 'Deleted Items $retentionDays Days' created successfully." "SUCCESS"
                }
                else {
                    Log-Message "Retention policy tag 'Deleted Items $retentionDays Days' already exists." "INFO"
                }
                if (-not (Get-RetentionPolicy -Identity "Deleted Items Retention Policy" -ErrorAction SilentlyContinue)) {
                    New-RetentionPolicy -Name "Deleted Items Retention Policy" -RetentionPolicyTagLinks "Deleted Items $retentionDays Days"
                    Log-Message "Retention policy 'Deleted Items Retention Policy' created successfully." "SUCCESS"
                }
                else {
                    Log-Message "Retention policy 'Deleted Items Retention Policy' already exists." "INFO"
                }
                Get-Mailbox -ResultSize Unlimited | ForEach-Object {
                    Set-Mailbox -Identity $_.Identity -RetentionPolicy "Deleted Items Retention Policy"
                    Log-Message "Retention policy applied to mailbox $($_.PrimarySmtpAddress)." "SUCCESS"
                }
            }
        },        
        @{ Name = "Enable Unified Audit Log Search"; Action = { 
                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled (ConvertTo-Boolean $Config.Exchange.UnifiedAuditLogSearch) 
            } 
        },
        @{ Name = "Configure Audit Log Retention"; Action = { 
                Set-OrganizationConfig -AuditDisabled $false
                Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit (ConvertTo-TimeSpan $Config.Exchange.AuditLogAgeLimit) 
            } 
        },
        @{ Name = "Enable External Sender Tags"; Action = { 
                Set-ExternalInOutlook -Enabled (ConvertTo-Boolean $Config.Exchange.ExternalSenderTags) 
            } 
        },
        @{ Name = "Create or Update Allow List for Admin Users (External Sender Tags)"; Action = { 
                Set-ExternalInOutlook -AllowList $Config.Exchange.ExternalSenderAllowList 
            } 
        },
        @{ Name = "Configure Azure AD Security Defaults"; Action = { 
                $params = @{
                    EnforceSecurityDefaults = (ConvertTo-Boolean $Config.AzureAD.EnforceSecurityDefaults) 
                }
                #needs fixingUpdate-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params 
            } 
        },
        @{ Name = "Create Break-Glass Account"; Action = {
            if ($Config.AzureAD.CreateBreakGlassAdmin.Enabled -eq $true) {
                $existingUser = Get-AzureADUser -Filter "UserPrincipalName eq '$($Config.AzureAD.CreateBreakGlassAdmin.UPN)'"
        
                if (-not $existingUser) {
                    $passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
                    $passwordProfile.Password = (ConvertTo-SecureString -String $Config.AzureAD.CreateBreakGlassAdmin.Password -AsPlainText -Force)
                    
                    New-AzureADUser -AccountEnabled $true -DisplayName $Config.AzureAD.CreateBreakGlassAdmin.DisplayName -MailNickName $Config.AzureAD.BreakGlassAdmin `
                        -UserPrincipalName "$($Config.AzureAD.CreateBreakGlassAdmin.UPN)" -PasswordProfile $passwordProfile
                    
                    $roleId = (Get-AzureADDirectoryRole -Filter "displayName eq 'Global Administrator'").ObjectId
                    $userId = (Get-AzureADUser -Filter "UserPrincipalName eq '$($Config.AzureAD.CreateBreakGlassAdmin.UPN)'").ObjectId
                    
                    Add-AzureADDirectoryRoleMember -ObjectId $roleId -RefObjectId $userId
                    
                    Log-Message "Break-Glass account '$($Config.AzureAD.CreateBreakGlassAdmin.UPN)' created and added to Global Administrator role." "INFO"
                }
                else {
                    Log-Message "Break-Glass account '$($Config.AzureAD.CreateBreakGlassAdmin.UPN)' already exists. Skipping creation." "INFO"
                }
            }
            else {
                Log-Message "Creation of Break-Glass account is disabled in the configuration. Skipping..." "INFO"
            }
        }}
        @{ Name = "Delete Old Devices (If Configured)"; Action = { 
                if (ConvertTo-Boolean $Config.AzureAD.DeleteStaleDevices) {
                    Get-AzureADDevice -All $true | Where-Object { $_.ApproximateLastSignInDate -lt (Get-Date).AddMonths(-3) } | `
                        ForEach-Object { Remove-AzureADDevice -ObjectId $_.ObjectId }
                }
            } 
        },
        @{ Name = "Create Non-Mail Groups in Azure AD"; Action = { 
                if ($Config.AzureAD.GroupCreation.CreateSecurityGroups.Enabled -eq $true) {
                    foreach ($group in $Config.AzureAD.GroupCreation.CreateSecurityGroups.Groups) {
                        New-AzureADGroup -DisplayName $group -MailEnabled $false -SecurityEnabled $true
                    }
                }
                else {
                    Log-Message "Skipping creation of non-mail security groups as per configuration." "INFO"
                }
            } 
        },
        @{ Name = "Create Mail-Enabled Security Groups"; Action = { 
                if ($Config.AzureAD.GroupCreation.CreateMailEnabledSecurityGroups.Enabled -eq $true) {
                    foreach ($group in $Config.AzureAD.GroupCreation.CreateMailEnabledSecurityGroups.Groups) {
                        New-DistributionGroup -Name $group
                    }
                }
                else {
                    Log-Message "Skipping creation of mail-enabled security groups as per configuration." "INFO"
                }
            } 
        },
        @{ Name = "Hide Admin Users from GAL"; Action = {
                foreach ($adminUser in $adminUsers) {
                    if ($adminUser) {
                        Set-Mailbox -Identity $adminUser -HiddenFromAddressListsEnabled $true
                        Log-Message "Successfully hid $adminUser from the Global Address List." "SUCCESS"
                    }
                    else {
                        Log-Message "Skipped an empty or null admin user entry." "WARNING"
                    }
                }
            }
        }        
        @{ Name = "Set Up Email Forwarding for Global Admin"; Action = {
                if ($Config.Exchange.ForwardAdminMails.Enabled -eq $true) {
                    foreach ($adminUser in $adminUsers) {
                        Set-Mailbox -Identity $adminUser -ForwardingAddress $Config.Exchange.ForwardAdminMails.To -DeliverToMailboxAndForward $true
                        Set-MailboxJunkEmailConfiguration -Identity $adminUser -Enabled $true
                    }
                }
                else {
                    Write-Host "Email forwarding for Global Admin is disabled in the configuration."
                }
            }
        }
        @{
            Name   = "Disable Shared Mailbox Logon"
            Action = {
            if ($Config.Exchange.BlockSharedMailboxLogon -eq $true) {
                $membershipRule = '(user.mailNickname -ne null) -and (user.userType -eq "Member") -and (user.mail -ne null) -and (user.userPrincipalName -contains "@") -and (user.assignedPlans -all (assignedPlan.servicePlanId -eq null))'
        
                # Create the dynamic group
                $group = New-MgGroup -DisplayName "Blocked Shared Mailboxes" `
                    -MailEnabled:$false `
                    -MailNickname "BlockedSharedMailboxes" `
                    -SecurityEnabled:$true `
                    -GroupTypes @("DynamicMembership") `
                    -MembershipRule $membershipRule `
                    -MembershipRuleProcessingState "On"
        
                Log-Message "Dynamic Group Created: $($group.DisplayName)" "INFO"
                    Log-Message "Starting sleep for 30 seconds to ensure the group is fully created and populated." "INFO"
                    Start-Sleep -Seconds 30
                Log-Message "Continuing..." "INFO"
        
                # Get the Group ID of the dynamic group
                $groupId = $group.Id
        
                # Define the policy
                $policy = @{
                    displayName     = "Block Sign-In for Shared Mailboxes"
                    state           = "enabled"
                    conditions      = @{
                        users = @{
                            includeGroups = @($groupId)
                        }
                    }
                    grantControls   = @{
                        operator        = "OR"
                        builtInControls = @("block")
                    }
                    sessionControls = @{}
                        scope           = @{
                            include = "all"
                        }
                }
        
                # Create the Conditional Access Policy
                Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body ($policy | ConvertTo-Json -Depth 5)
        
                Log-Message "Conditional Access Policy Created" "INFO"
            }
            }
        }
        
        @{ Name = "Set Regional Settings for All Mailboxes"; Action = { 
                Get-Mailbox -ResultSize Unlimited | ForEach-Object { 
                    Set-MailboxRegionalConfiguration -Identity $_.UserPrincipalName -Language $Config.MSOL.RegionalSettings.Language `
                        -TimeZone $Config.MSOL.RegionalSettings.TimeZone
                }
            } 
        },
        @{ Name = "Disable Creation of Org-Wide Teams"; Action = { 
                Set-CsTeamsChannelsPolicy -Identity Global -AllowOrgWideTeamCreation (ConvertTo-Boolean $Config.Teams.DefaultTeamSettings.AllowOrgWideTeamCreation)
            } 
        },
        @{ Name = "Configure Teams External Access and Guest Access"; Action = { 
                Set-CsTenantFederationConfiguration -AllowFederatedUsers (ConvertTo-Boolean $Config.Teams.DefaultTeamSettings.AllowExternalAccess)
                Set-CsTeamsClientConfiguration -Identity Global -AllowGuestUser (ConvertTo-Boolean $Config.Teams.DefaultTeamSettings.AllowGuestAccess)
                Set-CsTeamsMeetingConfiguration -Identity Global -DisableAnonymousJoin (ConvertTo-Boolean $Config.Teams.DisableAnonymousJoin)
            } 
        },
        @{ Name = "Set Default Storage Limits for SharePoint/OneDrive"; Action = { 
                Set-SPOTenant -OneDriveStorageQuota $Config.SharePointOneDrive.DefaultStorageLimit
            } 
        },
        @{ Name = "Configure SharePoint/OneDrive External Sharing"; Action = { 
                Set-SPOTenant -SharingCapability $Config.SharePointOneDrive.SharingCapability
                Set-SPOTenant -BccExternalSharingInvitations (ConvertTo-Boolean $Config.SharePointOneDrive.BccExternalSharingInvitations)
            } 
        },
        @{ Name = "Create Security Alert Policies"; Action = { 
                $params = @{
                    AdminActivities    = (ConvertTo-Boolean $Config.EnhancedSecurityAlerts.AdminActivities)
                    MalwareAlerts      = (ConvertTo-Boolean $Config.EnhancedSecurityAlerts.MalwareAlerts)
                    ThreatPolicies     = (ConvertTo-Boolean $Config.EnhancedSecurityAlerts.ThreatPolicies)
                    HighSensitivity    = (ConvertTo-Boolean $Config.EnhancedSecurityAlerts.HighSensitivity)
                    BasicInformational = (ConvertTo-Boolean $Config.EnhancedSecurityAlerts.BasicInformational)
                }
                New-ProtectionAlert @params
            } 
        },
        @{ Name = "Configure Auto-Expanding Archive"; Action = { 
                Set-OrganizationConfig -AutoExpandingArchive (ConvertTo-Boolean $Config.Exchange.AutoExpandingArchive)
            } 
        },
        @{ Name = "Enable Archive Mailbox for All Users"; Action = { 
                Get-Mailbox -ResultSize Unlimited -Filter { ArchiveStatus -Eq "None" } | Enable-Mailbox -Archive
            } 
        },
        @{ Name = "Enable Litigation Hold for All Eligible Mailboxes"; Action = { 
                Get-Mailbox -ResultSize Unlimited -Filter { LitigationHoldEnabled -Eq $false } | Set-Mailbox -LitigationHoldEnabled (ConvertTo-Boolean $Config.Exchange.LitigationHoldEnabled)
            } 
        }
    )

    foreach ($task in $tasks) {
        try {
            Log-Message "Applying $($task.Name)..." "INFO"
            & $task.Action
            Log-Message "$($task.Name) configuration applied successfully." "SUCCESS"
        }
        catch {
            Log-Message "Failed to apply $($task.Name) configuration: $_" "ERROR"
        }
    }
}
