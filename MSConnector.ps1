function Connect-TenantAdmin {
    param ([psobject]$Config = $null)

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
    }

    Import-Module ExchangeOnlineManagement

    if ($Config -ne $null) {
        $TenantAdminUsername = $Config.TenantAdmin.Username
        $TenantAdminPassword = $Config.TenantAdmin.Password | ConvertTo-SecureString -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($TenantAdminUsername, $TenantAdminPassword)
        Connect-ExchangeOnline -Credential $Credential
    }
    else {
        Connect-ExchangeOnline
    }

    $adminRole = Get-RoleGroup | Where-Object { $_.Name -eq "Organization Management" }

    if (-not $adminRole) {
        Write-Error "User does not have the necessary 'Organization Management' role."
        exit 1
    }
}

function Connect-ExchangeOnline {
    param ([pscredential]$Credential = $null)

    Import-Module ExchangeOnlineManagement

    if ($Credential -ne $null) {
        Connect-ExchangeOnline -Credential $Credential
    }
    else {
        Connect-ExchangeOnline
    }
}
