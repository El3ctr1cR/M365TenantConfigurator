function Connect-TenantAdmin {
    param ()

    $global:TenantAdminCredential = $null

    function Login-Interactive {
        if (-not $global:TenantAdminCredential) {
            $global:TenantAdminCredential = Get-Credential -Message "Please enter your tenant admin credentials."
        }
    }

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
            Import-Module $ModuleName
        }
        catch {
            Log-Message "Failed to import $ModuleName module: $_" "ERROR"
            exit 1
        }
    }

    # Only load modules once
    InstallAndImportModule "ExchangeOnlineManagement"
    InstallAndImportModule "AzureAD"
    InstallAndImportModule "MSOnline"
    InstallAndImportModule "MicrosoftTeams"

    # Interactive Login for all services
    Login-Interactive

    # Connection to Exchange Online
    try {
        Log-Message "Attempting to connect to Exchange Online..." "INFO"
        Connect-ExchangeOnline -Credential $global:TenantAdminCredential -ShowProgress:$false
        Log-Message "Connected to Exchange Online successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Exchange Online: $_" "ERROR"
        exit 1
    }

    # Connection to Azure AD
    try {
        Log-Message "Connecting to Azure AD..." "INFO"
        Connect-AzureAD -Credential $global:TenantAdminCredential
        Log-Message "Connected to Azure AD successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Azure AD: $_" "ERROR"
        exit 1
    }

    # Connection to MSOnline
    try {
        Log-Message "Connecting to MSOnline..." "INFO"
        Connect-MsolService -Credential $global:TenantAdminCredential
        Log-Message "Connected to MSOnline successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to MSOnline: $_" "ERROR"
        exit 1
    }

    # Connection to Microsoft Teams
    try {
        Log-Message "Connecting to Microsoft Teams..." "INFO"
        Connect-MicrosoftTeams -Credential $global:TenantAdminCredential
        Log-Message "Connected to Microsoft Teams successfully." "SUCCESS"
    }
    catch {
        Log-Message "Failed to connect to Microsoft Teams: $_" "ERROR"
        exit 1
    }
}
