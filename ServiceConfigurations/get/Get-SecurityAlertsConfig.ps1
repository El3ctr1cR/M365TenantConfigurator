function Get-SecurityAlertsConfig {
    $config = [PSCustomObject]@{
        AdminActivities    = Get-AlertPolicy -Filter "Name eq 'Admin Activities'"
        MalwareAlerts      = Get-AlertPolicy -Filter "Name eq 'Malware Alerts'"
        ThreatPolicies     = Get-AlertPolicy -Filter "Name eq 'Threat Policies'"
        HighSensitivity    = Get-AlertPolicy -Filter "Name eq 'High Sensitivity Alerts'"
        BasicInformational = Get-AlertPolicy -Filter "Name eq 'Basic Informational Alerts'"
    }
    return $config
}
