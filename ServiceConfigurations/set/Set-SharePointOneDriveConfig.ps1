function Set-SharePointOneDriveConfig {
    param ([Parameter(Mandatory=$true)][psobject]$Config)

    Set-SPOTenant -DefaultStorageQuota $Config.SharePointOneDrive.DefaultStorageLimit
    Set-SPOTenant -SharingCapability $Config.SharePointOneDrive.SharingCapability

    New-RetentionCompliancePolicy -Name "SharePoint and OneDrive Retention" -SharePointLocation $true -OneDriveLocation $true -RetentionDuration $Config.SharePointOneDrive.RetentionPolicy.SharePointOneDrive -RetentionAction Keep
    New-RetentionCompliancePolicy -Name "Email Retention" -ExchangeLocation $true -RetentionDuration $Config.SharePointOneDrive.RetentionPolicy.Email -RetentionAction Keep
}
