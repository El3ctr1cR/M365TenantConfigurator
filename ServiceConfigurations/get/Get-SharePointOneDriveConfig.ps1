function Get-SharePointOneDriveConfig {
    $config = [PSCustomObject]@{
        DefaultStorageLimit       = (Get-SPOTenant).DefaultStorageQuota
        SharingCapability         = (Get-SPOTenant).SharingCapability
        EmailRetentionPolicy      = Get-RetentionCompliancePolicy -Filter "ExchangeLocation -eq 'true'"
        SharePointRetentionPolicy = Get-RetentionCompliancePolicy -Filter "SharePointLocation -eq 'true' -and OneDriveLocation -eq 'true'"
    }
    return $config
}
