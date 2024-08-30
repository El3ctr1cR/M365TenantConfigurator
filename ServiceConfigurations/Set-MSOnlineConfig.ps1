function Set-MSOnlineConfig {
    param ([Parameter(Mandatory=$true)][psobject]$Config)

    Get-MsolUser -All | Where-Object { $_.IsLicensed -eq $false -and $_.UserPrincipalName -like "*@*" } | Set-MsolUser -UserPrincipalName $_.UserPrincipalName -AccountEnabled $false
    Get-MsolUser -All | Set-MsolUser -PreferredLanguage $Config.MSOL.RegionalSettings.Language -UsageLocation $Config.MSOL.RegionalSettings.TimeZone
}
