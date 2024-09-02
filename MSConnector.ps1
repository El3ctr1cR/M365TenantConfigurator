function Connect-TenantAdmin {
    param ()

    $global:SharePointAdminUrl = $null

    function InstallAndImportModule {
        param (
            [string]$ModuleName
        )

        Log-Message "Checking for module $ModuleName..." "INFO"

        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            try {
                Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
                Log-Message "$ModuleName module installed successfully." "SUCCESS"
            }
            catch {
                Log-Message "Failed to install $ModuleName module: $_" "ERROR"
                exit 1
            }
        }

        try {
            Log-Message "Importing module $ModuleName..." "INFO"
            Import-Module $ModuleName -Force
        }
        catch {
            Log-Message "Failed to import $ModuleName module: $_" "ERROR"
            exit 1
        }
    }

    function Get-ScriptDirectory {
        if ($MyInvocation.MyCommand.Path) {
            return Split-Path -Parent $MyInvocation.MyCommand.Path
        }
        return Get-Location
    }

    function Install-AzureCoreDependency {
        $scriptDirectory = Get-ScriptDirectory
        $libsDir = Join-Path $scriptDirectory "libs"
        $nugetExePath = Join-Path $libsDir "nuget.exe"
        $azureCoreDir = Join-Path $libsDir "Azure.Core.1.39.0"

        if (-not (Test-Path -Path $libsDir)) {
            New-Item -Path $libsDir -ItemType Directory | Out-Null
        }

        if (-not (Test-Path -Path $nugetExePath)) {
            Log-Message "Downloading NuGet CLI..." "INFO"
            Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $nugetExePath
            Log-Message "NuGet CLI downloaded successfully." "SUCCESS"
        }

        Log-Message "Clearing NuGet cache..." "INFO"
        & $nugetExePath locals all -clear

        Log-Message "Installing Azure.Core dependency..." "INFO"
        & $nugetExePath install Azure.Core -Version 1.39.0 -OutputDirectory $libsDir

        Log-Message "Azure.Core dependency installed successfully." "SUCCESS"

        $dllPath = Join-Path $azureCoreDir "lib/net472/Azure.Core.dll"
        if (Test-Path -Path $dllPath) {
            [System.Reflection.Assembly]::LoadFrom($dllPath)
            Log-Message "Azure.Core assembly loaded successfully." "SUCCESS"
        }
        else {
            Log-Message "Azure.Core assembly could not be found." "ERROR"
            exit 1
        }
    }

    function Ensure-AzureCoreDependency {
        $scriptDirectory = Get-ScriptDirectory
        $libsDir = Join-Path $scriptDirectory "libs"
        $azureCoreDir = Join-Path $libsDir "Azure.Core.1.39.0"

        if (-not (Test-Path -Path $azureCoreDir)) {
            Install-AzureCoreDependency
        }
        else {
            Log-Message "Azure.Core dependency already installed." "SUCCESS"
        }
    }

    Ensure-AzureCoreDependency

    Remove-Module -Name ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue

    InstallAndImportModule "Microsoft.Graph.Authentication"
    InstallAndImportModule "Microsoft.Graph.Identity.SignIns"

    InstallAndImportModule "ExchangeOnlineManagement"
    InstallAndImportModule "AzureAD"
    InstallAndImportModule "MSOnline"
    InstallAndImportModule "MicrosoftTeams"
    InstallAndImportModule "AIPService"

    $graphModules = @(
        "Microsoft.Graph.Identity.SignIns"
        "Microsoft.Graph.Intune"
        "Microsoft.Graph.DeviceManagement"
        "Microsoft.Graph.Compliance"
        "Microsoft.Graph.Users"
        "Microsoft.Graph.Groups"
        "Microsoft.Graph.Security"
    )

    foreach ($module in $graphModules) {
        InstallAndImportModule $module
    }

    $global:SharePointAdminUrl = Read-Host -Prompt "Please enter your SharePoint Online Admin URL (e.g., https://<tenant>-admin.sharepoint.com)"

    try {
        Log-Message "Attempting to connect to Exchange Online..." "INFO"
        Connect-ExchangeOnline -ShowProgress:$false
        Log-Message "Connected to Exchange Online successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Exchange Online: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to Azure AD..." "INFO"
        Connect-AzureAD
        Log-Message "Connected to Azure AD successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Azure AD: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to MSOnline..." "INFO"
        Connect-MsolService
        Log-Message "Connected to MSOnline successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to MSOnline: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to Microsoft Teams..." "INFO"
        Connect-MicrosoftTeams
        Log-Message "Connected to Microsoft Teams successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Microsoft Teams: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to AIPService..." "INFO"
        Connect-AipService
        Log-Message "Connected to AIPService successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to AIPService: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to Microsoft Graph..." "INFO"
        Connect-MgGraph -Scopes `
            "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", `
            "Organization.ReadWrite.All", "Device.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", `
            "SecurityEvents.ReadWrite.All", "MailboxSettings.ReadWrite", "Reports.Read.All", `
            "AuditLog.Read.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", `
            "TeamSettings.ReadWrite.All", "Sites.FullControl.All", "IdentityRiskyUser.ReadWrite.All", `
            "ThreatAssessment.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All", "Policy.Read.All"
        Log-Message "Connected to Microsoft Graph successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Microsoft Graph: $_" "ERROR"
        exit 1
    }

    try {
        Log-Message "Connecting to SharePoint Online..." "INFO"
        Connect-SPOService -Url $global:SharePointAdminUrl
        Log-Message "Connected to SharePoint Online successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to SharePoint Online: $_" "ERROR"
        exit 1
    }
}
