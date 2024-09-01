$ErrorActionPreference = 'Continue'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDirectory = Join-Path -Path $scriptDirectory -ChildPath "logs"
$serviceConfigDirectory = Join-Path -Path $scriptDirectory -ChildPath "ServiceConfiguration"

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

$logFileName = "log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
$logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

function Log-Message {
    param (
        [string]$Message,
        [string]$Type = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestamp] ($Type) $Message"

    switch ($Type) {
        "ERROR" { Write-Host $formattedMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $formattedMessage -ForegroundColor Green }
        "WARNING" { Write-Host $formattedMessage -ForegroundColor Yellow }
        default { Write-Host $formattedMessage }
    }

    Add-Content -Path $logFilePath -Value $formattedMessage
}

Log-Message "Starting tenant configuration script." "INFO"
Write-Host "/========================================================================\"
Write-Host "|| __  __ _____  __  ____    _____ _____ _   _    _    _   _ _____      ||"
Write-Host "|||  \/  |___ / / /_| ___|  |_   _| ____| \ | |  / \  | \ | |_   _|     ||"
Write-Host "||| |\/| | |_ \| '_ \___ \    | | |  _| |  \| | / _ \ |  \| | | |       ||"
Write-Host "||| |  | |___) | (_) |__) |   | | | |___| |\  |/ ___ \| |\  | | |       ||"
Write-Host "|||_|  |_|____/ \___/____/    |_| |_____| | \_/_/   \_\_| \_| |_|       ||"
Write-Host "||  ____ ___  _   _ _____ ___ ____ _   _ ____      _  _____ ___  ____   ||"
Write-Host "|| / ___/ _ \| \ | |  ___|_ _/ ___| | | |  _ \    / \|_   _/ _ \|  _ \  ||"
Write-Host "||| |  | | | |  \| | |_   | | |  _| | | | |_) |  / _ \ | || | | | |_) | ||"
Write-Host "||| |__| |_| | |\  |  _|  | | |_| | |_| |  _ <  / ___ \| || |_| |  _ <  ||"
Write-Host "|| \____\___/|_| \_|_|   |___\____|\___/|_| \_\/_/   \_\_| \___/|_| \_\ ||"
Write-Host "||                                                                      ||"
Write-Host "||                       Script by: El3ctr1cR                           ||"
Write-Host "||                GitHub: https://github.com/El3ctr1cR/                 ||"
Write-Host "\========================================================================/"

Log-Message "IMPORTANT WARNING: These changes cannot be reverted automatically unless there is a back-up!" "WARNING"
$confirmation = Read-Host "Have you set the config.yaml file correctly? (Y/N)"
if ($confirmation -ne "Y") {
    Log-Message "Configuration not confirmed. Exiting script." "WARNING"
    exit 1
}

$ConfigFilePath = "config.yaml"
if (-not (Test-Path $ConfigFilePath)) {
    Log-Message "Configuration file not found. Please provide a valid config.yaml file." "ERROR"
    exit 1
}

# Check if the powershell-yaml module is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Log-Message "powershell-yaml module not found. Installing module..." "INFO"
    try {
        Install-Module -Name powershell-yaml -Force -Scope CurrentUser
        Log-Message "powershell-yaml module installed successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to install powershell-yaml module: $_" "ERROR"
        exit 1
    }
}

Import-Module powershell-yaml

# Connect to the tenant admin
. .\MSConnector.ps1
Connect-TenantAdmin

# Import configuration scripts from the ServiceConfigurations directory
$configurationScripts = @(
    "Set-ServiceConfig.ps1"
)

foreach ($script in $configurationScripts) {
    $scriptPath = Join-Path -Path $serviceConfigDirectory -ChildPath $script
    if (Test-Path $scriptPath) {
        . $scriptPath
        Log-Message "$script imported successfully." "SUCCESS"
    }
    else {
        Log-Message "$script not found in $serviceConfigDirectory." "ERROR"
        exit 1
    }
}

# Execute the configuration scripts
$actions = @(
    @{ Name = "Service Configuration"; Action = { Set-ServiceConfig -ConfigPath $ConfigFilePath } }
)

foreach ($task in $actions) {
    try {
        Log-Message "Starting configuration for $($task.Name)..." "INFO"
        & $task.Action
        Log-Message "Configuration for $($task.Name) completed successfully." "SUCCESS"
    }
    catch {
        Log-Message "Configuration for $($task.Name) failed: $_" "ERROR"
    }
}

Log-Message "Tenant configuration script completed." "INFO"
