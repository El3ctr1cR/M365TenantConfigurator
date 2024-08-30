function Get-ExchangeOnlineConfig {
    $config = [PSCustomObject]@{
        SendFromAlias                    = (Get-OrganizationConfig).SendFromAliasEnabled
        PlusAddressing                   = (Get-OrganizationConfig).PlusAddressingEnabled
        MailTips                         = (Get-OrganizationConfig).MailTipsExternalRecipientsTipsEnabled
        ExternalSenderTags               = (Get-OrganizationConfig).ExternalInOutlook
        PublicComputerDetection          = (Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default).PublicComputersDetectionEnabled
        BlockAttachmentDownloadUnmanaged = (Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default).DownloadAttachmentsOnPublicComputersEnabled
        OutlookEventsRecognition         = (Get-OrganizationConfig).OutlookEventsEnabled
        ModernAuthentication             = (Get-OrganizationConfig).OAuth2ClientProfileEnabled
        BlockConsumerStorageOWA          = (Get-OrganizationConfig).OWABlockedStorageApps
        BlockOutlookPay                  = (Get-OrganizationConfig).OutlookClientSettingDisabled
        RetentionLimitDeletedItems       = (Get-RetentionPolicyTag -Identity "Default MRM Policy").AgeLimitForRetention.Days
        UnifiedAuditLogSearch            = (Get-OrganizationConfig).UnifiedAuditLogIngestionEnabled
    }
    return $config
}
