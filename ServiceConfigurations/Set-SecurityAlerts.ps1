function Set-SecurityAlerts {
    param ([Parameter(Mandatory = $true)][psobject]$Config)

    if ($Config.EnhancedSecurityAlerts.AdminActivities -eq $true) {
        New-AlertPolicy -Name "Admin Activities" -Category "Data Governance" -Severity "High" -IsEnabled $true
    }

    if ($Config.EnhancedSecurityAlerts.MalwareAlerts -eq $true) {
        New-AlertPolicy -Name "Malware Alerts" -Category "Threat Management" -Severity "High" -IsEnabled $true
    }

    if ($Config.EnhancedSecurityAlerts.ThreatPolicies -eq $true) {
        New-AlertPolicy -Name "Threat Policies" -Category "Threat Management" -Severity "High" -IsEnabled $true
    }

    if ($Config.EnhancedSecurityAlerts.HighSensitivity -eq $true) {
        New-AlertPolicy -Name "High Sensitivity Alerts" -Category "Data Loss Prevention" -Severity "High" -IsEnabled $true
    }

    if ($Config.EnhancedSecurityAlerts.BasicInformational -eq $true) {
        New-AlertPolicy -Name "Basic Informational Alerts" -Category "Information Governance" -Severity "Low" -IsEnabled $true
    }
}
