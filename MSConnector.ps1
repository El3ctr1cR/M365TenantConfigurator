function Connect-TenantAdmin {
    function Get-ScriptDirectory {
        if ($MyInvocation.MyCommand.Path) {
            return Split-Path -Parent $MyInvocation.MyCommand.Path
        }
        return Get-Location
    }
    $scriptDir = Get-ScriptDirectory
    $libsDir = "$scriptDir\libs"
    $nugetUrl = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
    $nugetPath = "$libsDir\nuget.exe"

    if (-not (Test-Path -Path $libsDir)) {
        New-Item -ItemType Directory -Path $libsDir | Out-Null
        Log-Message "Created libs directory at $libsDir" "INFO"
    }

    if (-not (Test-Path -Path $nugetPath)) {
        Log-Message "nuget.exe not found in $libsDir. Downloading..." "INFO"
        Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetPath
        if ($?) {
            Log-Message "Downloaded nuget.exe successfully." "SUCCESS"
        }
        else {
            Log-Message "Failed to download nuget.exe." "ERROR"
            exit 1
        }
    }
    else {
        Log-Message "nuget.exe is already present." "INFO"
    }

    $azureCoreVersion = "1.39.0"
    $azureCorePath = Join-Path -Path $libsDir -ChildPath "Azure.Core.$azureCoreVersion"

    if (-not (Test-Path -Path $azureCorePath)) {
        Log-Message "Azure.Core version $azureCoreVersion not found. Installing..." "INFO"
        & $nugetPath install Azure.Core -Version $azureCoreVersion -OutputDirectory $libsDir
        if ($?) {
            Log-Message "Azure.Core version $azureCoreVersion installed successfully." "SUCCESS"
        }
        else {
            Log-Message "Failed to install Azure.Core version $azureCoreVersion." "ERROR"
            exit 1
        }
    }
    else {
        Log-Message "Azure.Core version $azureCoreVersion is already installed." "INFO"
    }

    #$sharePointAdminUrl = Read-Host "Please enter your SharePoint admin URL"

    $modules = @(
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Intune",
        "Microsoft.Graph.DeviceManagement",
        "Microsoft.Graph.Compliance",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Security",
        "ExchangeOnlineManagement",
        "AzureAD",
        "MSOnline",
        "MicrosoftTeams",
        "AIPService"
    )

    function Install-Import-Module {
        param (
            [string]$moduleName
        )
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Log-Message "Module $moduleName not found. Installing..." "INFO"
            Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
            if ($?) {
                Log-Message "Module $moduleName installed successfully." "SUCCESS"
            }
            else {
                Log-Message "Failed to install module $moduleName." "ERROR"
                exit 1
            }
        }
        else {
            Log-Message "Module $moduleName is already installed." "INFO"
        }
    
        Import-Module -Name $moduleName
        if ($?) {
            Log-Message "Module $moduleName imported successfully." "SUCCESS"
        }
        else {
            Log-Message "Failed to import module $moduleName." "ERROR"
            exit 1
        }
    }

    foreach ($module in $modules) {
        Install-Import-Module -moduleName $module
    }

    $msGraphScopes = "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", `
        "Organization.ReadWrite.All", "Device.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", `
        "SecurityEvents.ReadWrite.All", "MailboxSettings.ReadWrite", "Reports.Read.All", `
        "AuditLog.Read.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", `
        "TeamSettings.ReadWrite.All", "Sites.FullControl.All", "IdentityRiskyUser.ReadWrite.All", `
        "ThreatAssessment.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All", "Policy.Read.All"

    Connect-MgGraph -Scopes $msGraphScopes
    if ($?) {
        Log-Message "Connected to Microsoft Graph successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to Microsoft Graph." "ERROR"
        exit 1
    }

    Connect-ExchangeOnline
    if ($?) {
        Log-Message "Connected to Exchange Online successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to Exchange Online." "ERROR"
        exit 1
    }

    Connect-AzureAD
    if ($?) {
        Log-Message "Connected to Azure AD successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to Azure AD." "ERROR"
        exit 1
    }

    Connect-MsolService
    if ($?) {
        Log-Message "Connected to MSOnline successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to MSOnline." "ERROR"
        exit 1
    }

    Connect-MicrosoftTeams
    if ($?) {
        Log-Message "Connected to Microsoft Teams successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to Microsoft Teams." "ERROR"
        exit 1
    }

    Connect-AipService
    if ($?) {
        Log-Message "Connected to AIPService successfully." "SUCCESS"
    }
    else {
        Log-Message "Failed to connect to AIPService." "ERROR"
        exit 1
    }
}