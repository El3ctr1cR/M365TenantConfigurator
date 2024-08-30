function Connect-TenantAdmin {
    param ([Parameter(Mandatory = $true)][psobject]$Config)

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
    }

    Import-Module ExchangeOnlineManagement

    Connect-ExchangeOnline -UserPrincipalName $Config.TenantAdmin.Username

    $adminRole = Get-RoleGroup | Where-Object { $_.Name -eq "Organization Management" }

    if (-not $adminRole) {
        Write-Error "User does not have the necessary 'Organization Management' role."
        exit 1
    }
}


function Connect-ExchangeOnline {
    param ([Parameter(Mandatory = $true)][pscredential]$Credential)

    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -Credential $Credential
}
