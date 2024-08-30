function Get-TeamsConfig {
    $config = [PSCustomObject]@{
        DefaultTeamSettings = Get-CsTeamsClientConfiguration | Select-Object AllowGuestUser, AllowExternalUser
    }
    return $config
}
