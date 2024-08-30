function Set-ExchangeOnlineConfig {
    param ([Parameter(Mandatory=$true)][psobject]$Config)

    Enable-OrganizationCustomization

    Set-OrganizationConfig -SendFromAliasEnabled $Config.Exchange.SendFromAlias
    Set-OrganizationConfig -FocusedInboxOn $false
    Set-OrganizationConfig -DistributionGroupNamingPolicy $Config.Exchange.DistributionGroupNamingPolicy

    Set-OrganizationConfig -PlusAddressingEnabled $Config.Exchange.PlusAddressing
    Set-OrganizationConfig -MailTipsExternalRecipientsTipsEnabled $Config.Exchange.MailTips
    Set-ExternalInOutlook -Enable $Config.Exchange.ExternalSenderTags

    Set-Mailbox -Identity $Config.Exchange.AdminMailbox -AuditEnabled $true -AuditLogAgeLimit $Config.Exchange.AuditLogAgeLimit
    Get-Mailbox -ResultSize Unlimited | Set-MailboxAuditBypassAssociation -AuditEnabled $true

    Set-OWAMailboxPolicy -Identity OwaMailboxPolicy-Default -PublicComputersDetectionEnabled $Config.Exchange.PublicComputerDetection
    Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -DownloadAttachmentsOnPublicComputersEnabled $Config.Exchange.BlockAttachmentDownloadUnmanaged
    Set-OrganizationConfig -OutlookEventsEnabled $Config.Exchange.OutlookEventsRecognition
    Set-OrganizationConfig -ModernAuthentication $Config.Exchange.ModernAuthentication
    Set-OrganizationConfig -BlockConsumerStorage $Config.Exchange.BlockConsumerStorageOWA
    Set-OrganizationConfig -BlockOutlookPay $Config.Exchange.BlockOutlookPay
    Set-RetentionPolicy -Identity "Default MRM Policy" -RetentionPolicyTagLinks @{Add="$($Config.Exchange.RetentionLimitDeletedItems) days"}
    Set-OrganizationConfig -UnifiedAuditLogIngestionEnabled $Config.Exchange.UnifiedAuditLogSearch
}
