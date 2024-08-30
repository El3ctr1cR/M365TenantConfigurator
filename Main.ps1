$ErrorActionPreference = 'Stop'
$ConfigFilePath = "config.json"

if (-not (Test-Path $ConfigFilePath)) {
    Write-Error "Configuration file not found. Please provide a valid config.json file."
    exit 1
}

$Config = Get-Content -Raw -Path $ConfigFilePath | ConvertFrom-Json

. .\MSConnector.ps1
. .\ServiceConfigurations\Set-ExchangeOnlineConfig.ps1
. .\ServiceConfigurations\Set-AzureADConfig.ps1
. .\ServiceConfigurations\Set-MSOnlineConfig.ps1
. .\ServiceConfigurations\Set-TeamsConfig.ps1
. .\ServiceConfigurations\Set-SharePointOneDriveConfig.ps1
. .\ServiceConfigurations\Set-SecurityAlerts.ps1

Connect-TenantAdmin -Config $Config
Set-ExchangeOnlineConfig -Config $Config
Set-AzureADConfig -Config $Config
Set-MSOnlineConfig -Config $Config
Set-TeamsConfig -Config $Config
Set-SharePointOneDriveConfig -Config $Config
Set-SecurityAlerts -Config $Config

Write-Output "Tenant configuration completed successfully."
