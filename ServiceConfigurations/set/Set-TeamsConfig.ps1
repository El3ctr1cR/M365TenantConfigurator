function Set-TeamsConfig {
    param ([Parameter(Mandatory=$true)][psobject]$Config)

    Set-CsTeamsClientConfiguration -AllowGuestUser $Config.Teams.DefaultTeamSettings.AllowGuestAccess
    Set-CsTeamsClientConfiguration -AllowExternalUser $Config.Teams.DefaultTeamSettings.AllowExternalAccess
}
