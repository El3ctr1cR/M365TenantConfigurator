$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$logDirectory = Join-Path -Path $scriptDirectory -ChildPath "logs"
$backupDirectory = Join-Path -Path $scriptDirectory -ChildPath "backups"

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

if (-not (Test-Path -Path $backupDirectory)) {
    New-Item -Path $backupDirectory -ItemType Directory
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

Write-Host "1. Execute config.json"
Write-Host "2. Create a tenant back-up"
Write-Host "3. Restore a tenant back-up"
$choice = Read-Host "Choose an option"

switch ($choice) {
    1 {
        Write-Host "Executing configuration..."
        
        $ConfigFilePath = "config.json"
        if (-not (Test-Path $ConfigFilePath)) {
            Write-Error "Configuration file not found. Please provide a valid config.json file."
            Stop-Transcript
            exit 1
        }

        $Config = Get-Content -Raw -Path $ConfigFilePath | ConvertFrom-Json

        . .\MSConnector.ps1
        . .\ServiceConfigurations\set\Set-ExchangeOnlineConfig.ps1
        . .\ServiceConfigurations\set\Set-AzureADConfig.ps1
        . .\ServiceConfigurations\set\Set-MSOnlineConfig.ps1
        . .\ServiceConfigurations\set\Set-TeamsConfig.ps1
        . .\ServiceConfigurations\set\Set-SharePointOneDriveConfig.ps1
        . .\ServiceConfigurations\set\Set-SecurityAlerts.ps1

        Connect-TenantAdmin -Config $Config
        Set-ExchangeOnlineConfig -Config $Config
        Set-AzureADConfig -Config $Config
        Set-MSOnlineConfig -Config $Config
        Set-TeamsConfig -Config $Config
        Set-SharePointOneDriveConfig -Config $Config
        Set-SecurityAlerts -Config $Config

        Write-Output "Tenant configuration completed successfully."
    }
    2 {
        . .\MSConnector.ps1
        . .\ServiceConfigurations\get\Get-ExchangeOnlineConfig.ps1
        . .\ServiceConfigurations\get\Get-AzureADConfig.ps1
        . .\ServiceConfigurations\get\Get-MSOnlineConfig.ps1
        . .\ServiceConfigurations\get\Get-TeamsConfig.ps1
        . .\ServiceConfigurations\get\Get-SharePointOneDriveConfig.ps1
        . .\ServiceConfigurations\get\Get-SecurityAlertsConfig.ps1
    
        Write-Host "Creating a backup of the current tenant configuration..."
    
        Connect-TenantAdmin
    
        $currentConfig = [PSCustomObject]@{
            Exchange   = Get-ExchangeOnlineConfig
            AzureAD    = Get-AzureADConfig
            MSOnline   = Get-MSOnlineConfig
            Teams      = Get-TeamsConfig
            SharePoint = Get-SharePointOneDriveConfig
            Security   = Get-SecurityAlertsConfig
        }
    
        $backupFileName = "backup-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').json"
        $backupFilePath = Join-Path -Path $backupDirectory -ChildPath $backupFileName
    
        $currentConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupFilePath
    
        Write-Host "Backup created: $backupFilePath"
    }
    3 {
        $backups = Get-ChildItem -Path $backupDirectory -Filter "*.json"

        if ($backups.Count -eq 0) {
            Write-Host "No backups found in $backupDirectory"
            Stop-Transcript
            exit 1
        }

        Write-Host "Available backups:"
        $backups | ForEach-Object { Write-Host "$($_.Name)" }

        $backupChoice = Read-Host "Enter the name of the backup file to restore"
        $selectedBackup = Join-Path -Path $backupDirectory -ChildPath $backupChoice

        if (-not (Test-Path $selectedBackup)) {
            Write-Host "Backup file not found: $selectedBackup"
            Stop-Transcript
            exit 1
        }

        Copy-Item -Path $selectedBackup -Destination "config.json" -Force
        Write-Host "Configuration restored from backup: $selectedBackup"
    }
    default {
        Write-Host "Invalid choice. Exiting..."
        Stop-Transcript
        exit 1
    }
}

Stop-Transcript
