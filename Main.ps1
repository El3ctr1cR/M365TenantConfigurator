$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$logDirectory = Join-Path -Path $scriptDirectory -ChildPath "logs"
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

$logFileName = "log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
$logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

Start-Transcript -Path $logFilePath -Append

Write-Host "/========================================================================\"
Write-Host "|| __  __ _____  __  ____    _____ _____ _   _    _    _   _ _____      ||"
Write-Host "|||  \/  |___ / / /_| ___|  |_   _| ____| \ | |  / \  | \ | |_   _|     ||"
Write-Host "||| |\/| | |_ \| '_ \___ \    | | |  _| |  \| | / _ \ |  \| | | |       ||"
Write-Host "||| |  | |___) | (_) |__) |   | | | |___| |\  |/ ___ \| |\  | | |       ||"
Write-Host "|||_|  |_|____/ \___/____/    |_| |_____|_| \_/_/   \_\_| \_| |_|       ||"
Write-Host "||  ____ ___  _   _ _____ ___ ____ _   _ ____      _  _____ ___  ____   ||"
Write-Host "|| / ___/ _ \| \ | |  ___|_ _/ ___| | | |  _ \    / \|_   _/ _ \|  _ \  ||"
Write-Host "||| |  | | | |  \| | |_   | | |  _| | | | |_) |  / _ \ | || | | | |_) | ||"
Write-Host "||| |__| |_| | |\  |  _|  | | |_| | |_| |  _ <  / ___ \| || |_| |  _ <  ||"
Write-Host "|| \____\___/|_| \_|_|   |___\____|\___/|_| \_\/_/   \_\_| \___/|_| \_\ ||"
Write-Host "||                                                                      ||"
Write-Host "||                       Script by: El3ctr1cR                           ||"
Write-Host "||                GitHub: https://github.com/El3ctr1cR/                 ||"
Write-Host "\========================================================================/"

$confirmation = Read-Host "Confirm whether config.json is edited and ready (Y/N)"
if ($confirmation -notin @('Y', 'y')) {
    Write-Host "Please edit the config.json file and then re-run the script."
    Stop-Transcript
    exit 1
}

$ConfigFilePath = "config.json"
if (-not (Test-Path $ConfigFilePath)) {
    Write-Error "Configuration file not found. Please provide a valid config.json file."
    Stop-Transcript
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

Stop-Transcript