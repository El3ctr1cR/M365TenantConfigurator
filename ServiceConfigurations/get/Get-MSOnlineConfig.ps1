function Get-MSOnlineConfig {
    $config = [PSCustomObject]@{
        SharedMailboxSignInDisabled = Get-MsolUser -All | Where-Object { $_.UserType -eq 'Shared' } | Select-Object UserPrincipalName, BlockCredential
        RegionalSettings            = Get-MsolUser -All | Select-Object UserPrincipalName, PreferredLanguage, UsageLocation
    }
    return $config
}
