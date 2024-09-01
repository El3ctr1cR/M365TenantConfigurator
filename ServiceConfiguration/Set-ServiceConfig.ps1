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

    $adminRoles = @("Organization Management", "Exchange Admins")
    $adminUsers = @()
    foreach ($role in $adminRoles) {
        $roleMembers = Get-RoleGroupMember -Identity $role
        $adminUsers += $roleMembers | Select-Object -ExpandProperty UserPrincipalName
    }
    $adminUsers = $adminUsers | Sort-Object -Unique

    $tasks = @(
        @{ Name = "Enable Organization Customization"; Action = { 
                $orgCustomization = Get-OrganizationConfig
                if ($orgCustomization.IsMultiGeoConfigurationEnabled -eq $false) {
                    Enable-OrganizationCustomization
                    Log-Message "Organization Customization enabled successfully." "SUCCESS"
                } else {
                    Log-Message "Organization Customization is already enabled." "INFO"
                }
            } 
        },
        #needs fixing@{ Name = "Enable AIP Service"; Action = { 
        #needs fixing        $aipServiceStatus = Get-AipServiceStatus
        #needs fixing        if ($aipServiceStatus.IsEnabled -eq $false) {
        #needs fixing            Enable-AipService
        #needs fixing            Log-Message "AIP Service enabled successfully." "SUCCESS"
        #needs fixing        } else {
        #needs fixing            Log-Message "AIP Service is already enabled." "INFO"
        #needs fixing        }
        #needs fixing    } 
        #needs fixing},        
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
        @{ Name   = "Set Retention Limit on Deleted Items"; Action = { 
                $retentionDays = $Config.Exchange.RetentionLimitDeletedItems
                $retentionDaysString = $Config.Exchange.RetentionLimitDeletedItems.ToString
                if (-not (Get-RetentionPolicyTag -Name "Deleted Items $retentionDaysString Days" -ErrorAction SilentlyContinue)) {
                    New-RetentionPolicyTag -Name "Deleted Items $retentionDaysString Days" -RetentionAction PermanentlyDelete -AgeLimitForRetention $retentionDays -Type DeletedItems
                    Log-Message "Retention policy tag 'Deleted Items $retentionDaysString Days' created successfully." "SUCCESS"
                }
                else {
                    Log-Message "Retention policy tag 'Deleted Items $retentionDaysString Days' already exists." "INFO"
                }
                if (-not (Get-RetentionPolicy -Name "Deleted Items Retention Policy" -ErrorAction SilentlyContinue)) {
                    New-RetentionPolicy -Name "Deleted Items Retention Policy" -RetentionPolicyTagLinks "Deleted Items $retentionDaysString Days"
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
                New-AzureADUser -AccountEnabled $true -DisplayName $Config.AzureAD.BreakGlassAdmin -MailNickName $Config.AzureAD.BreakGlassAdmin `
                    -UserPrincipalName "$($Config.AzureAD.BreakGlassAdminEmail)" -PasswordProfile (New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile `
                        -ArgumentList ($true, (ConvertTo-SecureString -String $Config.AzureAD.BreakGlassPassword -AsPlainText -Force)))
                Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole -Filter "displayName eq 'Global Administrator'").ObjectId `
                    -RefObjectId (Get-AzureADUser -Filter "UserPrincipalName eq '$($Config.AzureAD.BreakGlassAdminEmail)'").ObjectId
            } 
        },
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
                } else {
                    Log-Message "Skipping creation of non-mail security groups as per configuration." "INFO"
                }
            } 
        },
        @{ Name = "Create Mail-Enabled Security Groups";  Action = { 
                if ($Config.AzureAD.GroupCreation.CreateMailEnabledSecurityGroups.Enabled -eq $true) {
                    foreach ($group in $Config.AzureAD.GroupCreation.CreateMailEnabledSecurityGroups.Groups) {
                        New-DistributionGroup -Name $group
                    }
                } else {
                    Log-Message "Skipping creation of mail-enabled security groups as per configuration." "INFO"
                }
            } 
        },
               
        @{ Name = "Add Admin Users to Groups"; Action = { 
                foreach ($group in $Config.AzureAD.SecurityGroups) {
                    Add-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "DisplayName eq '$group'").ObjectId -RefObjectId $Config.AzureAD.BreakGlassAdmin
                    Add-DistributionGroupMember -Identity $group -Member $Config.AzureAD.BreakGlassAdmin
                }
            } 
        },
        @{ Name = "Grant Admin Access to All Mailboxes"; Action = {
                $mailboxPlans = Get-MailboxPlan
                foreach ($plan in $mailboxPlans) {
                    Write-Host "Processing mailbox plan: $($plan.DisplayName)"
                    $mailboxes = Get-Mailbox -MailboxPlan $plan.Identity
                    foreach ($mailbox in $mailboxes) {
                        foreach ($adminUser in $adminUsers) {
                            Add-MailboxPermission -Identity $mailbox.UserPrincipalName -User $adminUser -AccessRights FullAccess -InheritanceType All -AutoMapping $false
                        }
                    }
                    foreach ($adminUser in $adminUsers) {
                        Set-MailboxPlan -Identity $plan.Identity -GrantSendOnBehalfTo $adminUser
                    }
                }
            }
        },
        @{ Name = "Hide Admin Users from GAL"; Action = {
                foreach ($adminUser in $adminUsers) {
                    Set-Mailbox -Identity $adminUser -HiddenFromAddressListsEnabled $true
                }
            }
        },
        @{ Name = "Set Up Email Forwarding for Global Admin"; Action = {
                if ($Config.Exchange.ForwardAdminMails.Enabled -eq $true) {
                    foreach ($adminUser in $adminUsers) {
                        Set-Mailbox -Identity $adminUser -ForwardingAddress $Config.Exchange.ForwardAdminMails.To -DeliverToMailboxAndForward $true
                        Set-MailboxJunkEmailConfiguration -Identity $adminUser -Enabled $true
                    }
                } else {
                    Write-Host "Email forwarding for Global Admin is disabled in the configuration."
                }
            }
        }
        @{ Name = "Disable Shared Mailbox Logon"; Action = {
                if ($Config.Exchange.BlockSharedMailboxLogon -eq $true) {
                    Select-MgProfile -Name "beta"
        
                    $groupName = "Shared Mailboxes"
                    $dynamicRule = "(user.mailNickname -ne null) and (user.mailEnabled -eq true) and (user.userType -eq 'Member')"
        
                    $group = Get-MgGroup -Filter "displayName eq '$groupName'"
        
                    if (-not $group) {
                        $group = New-MgGroup -DisplayName $groupName -MailEnabled $false -SecurityEnabled $true `
                            -GroupTypes @("DynamicMembership") -MembershipRule $dynamicRule -MembershipRuleProcessingState "On"
                    }
        
                    $policyName = "Block Sign-ins for Shared Mailboxes"
                    $policy = Get-MgConditionalAccessPolicy -Filter "displayName eq '$policyName'"
        
                    if (-not $policy) {
                        $conditions = @{
                            Users = @{
                                IncludeGroups = @($group.Id)
                            }
                            Applications = @{
                                IncludeApplications = @("*")
                            }
                        }
        
                        $grantControls = @{
                            Operator        = "OR"
                            BuiltInControls = @("Block")
                        }
        
                        $sessionControl = @{
                            SignInFrequency = @{
                                Value = "Everytime"
                            }
                        }
        
                        $newPolicy = @{
                            DisplayName     = $policyName
                            State           = "enabled"
                            Conditions      = $conditions
                            GrantControls   = $grantControls
                            SessionControls = $sessionControl
                        }
        
                        New-MgConditionalAccessPolicy -BodyParameter $newPolicy
                    }
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
            & $task.Action
            Log-Message "$($task.Name) configuration applied successfully." "SUCCESS"
        }
        catch {
            Log-Message "Failed to apply $($task.Name) configuration: $_" "ERROR"
        }
    }
}
