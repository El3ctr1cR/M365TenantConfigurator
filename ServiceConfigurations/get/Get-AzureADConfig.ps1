function Get-AzureADConfig {
    $config = [PSCustomObject]@{
        BreakGlassAdmin           = (Get-AzureADMSGroup -Filter "displayName eq 'MSPNameBG'").DisplayName
        SecurityGroups            = Get-AzureADMSGroup -Filter "securityEnabled eq true"
        GlobalAdmins              = Get-AzureADDirectoryRole -Filter "displayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
        GroupCreationRestrictions = Get-AzureADDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }
    }
    return $config
}
