function Set-AzureADConfig {
    param ([Parameter(Mandatory=$true)][psobject]$Config)

    New-AzureADMSGroup -DisplayName $Config.AzureAD.BreakGlassAdmin -MailEnabled $false -SecurityEnabled $true

    if ($Config.AzureAD.DeleteStaleDevices) {
        Get-AzureADDevice -All $true | Where-Object { $_.ApproximateLastSignInDate -lt (Get-Date).AddMonths(-6) } | Remove-AzureADDevice
    }

    foreach ($Group in $Config.AzureAD.SecurityGroups) {
        New-AzureADMSGroup -DisplayName $Group -MailEnabled $false -SecurityEnabled $true
    }

    Add-AzureADMSDirectoryRole -RoleTemplateId (Get-AzureADDirectoryRoleTemplate | Where-Object {$_.DisplayName -eq "Global Administrator"}).Id -ObjectId (Get-AzureADUser -ObjectId $Config.TenantAdmin.Username).ObjectId
    Add-AzureADMSDirectoryRole -RoleTemplateId (Get-AzureADDirectoryRoleTemplate | Where-Object {$_.DisplayName -eq "User Account Administrator"}).Id -ObjectId (Get-AzureADUser -ObjectId $Config.TenantAdmin.Username).ObjectId

    Set-AzureADUser -ObjectId $Config.TenantAdmin.Username -MailNickName $null -HideFromAddressListsEnabled $true
}
