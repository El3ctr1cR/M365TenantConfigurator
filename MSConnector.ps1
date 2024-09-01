function Connect-TenantAdmin {
    param ()

    $global:SharePointAdminUrl = $null

    function InstallAndImportModule {
        param (
            [string]$ModuleName
        )

        Write-Host "Checking for module $ModuleName..." -ForegroundColor Yellow

        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            try {
                Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
                Write-Host "$ModuleName module installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to install $ModuleName module: $_" -ForegroundColor Red
                exit 1
            }
        }

        try {
            Write-Host "Importing module $ModuleName..." -ForegroundColor Yellow
            Import-Module $ModuleName -Force
        }
        catch {
            Write-Host "Failed to import $ModuleName module: $_" -ForegroundColor Red
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

        # Ensure the libs directory exists
        if (-not (Test-Path -Path $libsDir)) {
            New-Item -Path $libsDir -ItemType Directory | Out-Null
        }

        # Download nuget.exe if it doesn't exist
        if (-not (Test-Path -Path $nugetExePath)) {
            Write-Host "Downloading NuGet CLI..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $nugetExePath
            Write-Host "NuGet CLI downloaded successfully." -ForegroundColor Green
        }

        # Clear NuGet cache
        Write-Host "Clearing NuGet cache..." -ForegroundColor Yellow
        & $nugetExePath locals all -clear

        # Install Azure.Core dependency
        Write-Host "Installing Azure.Core dependency..." -ForegroundColor Yellow
        & $nugetExePath install Azure.Core -Version 1.39.0 -OutputDirectory $libsDir

        Write-Host "Azure.Core dependency installed successfully." -ForegroundColor Green

        # Load the Azure.Core assembly
        $dllPath = Join-Path $azureCoreDir "lib/net472/Azure.Core.dll"
        if (Test-Path -Path $dllPath) {
            [System.Reflection.Assembly]::LoadFrom($dllPath)
            Write-Host "Azure.Core assembly loaded successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Azure.Core assembly could not be found." -ForegroundColor Red
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
            Write-Host "Azure.Core dependency already installed." -ForegroundColor Green
        }
    }

    Ensure-AzureCoreDependency

    Remove-Module -Name ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue

    InstallAndImportModule "Microsoft.Graph.Authentication"

    InstallAndImportModule "ExchangeOnlineManagement"
    InstallAndImportModule "AzureAD"
    InstallAndImportModule "MSOnline"
    InstallAndImportModule "MicrosoftTeams"

    $graphModules = @(
        "Microsoft.Graph.Identity.SignIns"
        "Microsoft.Graph.Intune"
        "Microsoft.Graph.DeviceManagement"
        "Microsoft.Graph.Compliance"
        "Microsoft.Graph.Users"
        "Microsoft.Graph.Groups"
        "Microsoft.Graph.Authentication"
        "Microsoft.Graph.Security"
    )

    foreach ($module in $graphModules) {
        InstallAndImportModule $module
    }

    $global:SharePointAdminUrl = Read-Host -Prompt "Please enter your SharePoint Online Admin URL (e.g., https://<tenant>-admin.sharepoint.com)"

    try {
        Write-Host "Attempting to connect to Exchange Online..." -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowProgress:$false
        Write-Host "Connected to Exchange Online successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Exchange Online: $_" -ForegroundColor Red
        exit 1
    }

    try {
        Write-Host "Connecting to Azure AD..." -ForegroundColor Yellow
        Connect-AzureAD
        Write-Host "Connected to Azure AD successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Azure AD: $_" -ForegroundColor Red
        exit 1
    }

    try {
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        Connect-MsolService
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to MSOnline: $_" -ForegroundColor Red
        exit 1
    }

    try {
        Write-Host "Connecting to Microsoft Teams..." -ForegroundColor Yellow
        Connect-MicrosoftTeams
        Write-Host "Connected to Microsoft Teams successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Microsoft Teams: $_" -ForegroundColor Red
        exit 1
    }

    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes `
            "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", `
            "Organization.ReadWrite.All", "Device.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", `
            "SecurityEvents.ReadWrite.All", "MailboxSettings.ReadWrite", "Reports.Read.All", `
            "AuditLog.Read.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", `
            "TeamSettings.ReadWrite.All", "Sites.FullControl.All", "IdentityRiskyUser.ReadWrite.All", `
            "ThreatAssessment.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All"
        Write-Host "Connected to Microsoft Graph successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
        exit 1
    }

    try {
        Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow
        Connect-SPOService -Url $global:SharePointAdminUrl
        Write-Host "Connected to SharePoint Online successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to SharePoint Online: $_" -ForegroundColor Red
        exit 1
    }
}
