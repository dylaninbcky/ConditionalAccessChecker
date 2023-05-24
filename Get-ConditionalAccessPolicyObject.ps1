Function Get-ConditionalAccesspolicyObject {
    [CmdletBinding()]
    Param(
        $ExportLocation
    )
    Connect-AzureAD
    Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All'
    $allpolicies = Get-AzureADMSConditionalAccessPolicy 
    $array = @()
    foreach ($policy in $allpolicies) {
        #HTTP request inside the PSCustomobjects are not allowed. Setting variables at the beginning of the loop.
        #Not setting them in oneliners in case later on we want to do something with these variables.
        #checking if variables arent empty, because when you send a HTTP request to azure with an empty variable i cannot let it skip the error, even with Erroraction
        if ($policy.Conditions.Applications.IncludeApplications) {
            if ($policy.Conditions.Applications.IncludeApplications -ne "All") {
                $IncludeApp = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Applications.IncludeApplications -ErrorAction Continue
            }
            else {
                $IncludeApp = "Users set to All" 
            }
        }
        else {
            $IncludeApp = "N/A"
        }
        if ($policy.Conditions.Users.IncludeUsers) {
            if ($policy.Conditions.Users.IncludeUsers -ne "All") {
                $IncludeApp = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Users.IncludeUsers -ErrorAction Continue
            }
            else {
                $IncludeUsers = "Users set to All" 
            }
        }
        else {
            $IncludeUsers = "N/A"
        }
        if ($policy.Conditions.Users.ExcludeUsers) {
            $ExcludeUsers = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.users.Excludeusers -ErrorAction Continue
        }
        else {
            $ExcludeUsers = "N/A"
        }
        if ($policy.Conditions.Users.IncludeGroups) {
            $IncludeGroups = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Users.IncludeGroups -ErrorAction Continue
        }
        else {
            $IncludeGroups = "N/A"
        }
        if ($policy.Conditions.Users.ExcludeGroups) {
            $ExludeGroups = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Users.ExcludeGroups -ErrorAction Continue
        }
        else {
            $ExludeGroups = "N/A"
        }
        if ($policy.Conditions.Users.IncludeRoles) {
            $IncludeRoles = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Users.IncludeRoles -ErrorAction Continue
        }
        else {
            $IncludeRoles = "N/A"
        }
        if ($policy.Conditions.Users.ExcludeRoles) {
            $ExcludeRoles = Get-AzureADObjectByObjectId -ObjectIds $policy.Conditions.Users.ExcludeRoles -ErrorAction Continue
        }
        else {
            $ExcludeRoles = "N/A"
        }


        if ($policy.Conditions.Locations.Includelocations) {
            foreach ($loca in $policy.Conditions.Locations.IncludeLocations) {
                if ($loca -ne "All") {
                    $IncludeLocations += (Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $loca -ErrorAction Continue).DisplayName
                    $IncludeLocations += ";"
                }
                else {
                    $IncludeLocations = "All"
                }
            }
        }
        else {
            $IncludeLocations = "N/A"
        }

        ##setting the Exlude Locations
        if ($policy.Conditions.Locations.ExcludeLocations) {
            foreach ($loca in $policy.Conditions.Locations.ExcludeLocations) {
                if ($loca -ne "All") {
                    $Excludelocations += (Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $loca -ErrorAction Continue).DisplayName
                    $Excludelocations += ";"
                }
                else {
                    $Excludelocations = "All"
                }
            }
        }
        else {
            $Excludelocations = "N/A"
        }
        #building output object
        $array += [PSCustomObject]@{
            ID                                             = $policy.ID
            DisplayName                                    = $policy.DisplayName
            State                                          = $policy.State
            IncludedAppid                                  = $policy.Conditions.Applications.IncludeApplications -join ','
            IncludeApp                                     = $IncludeApp.DisplayName
            Userids                                        = $policy.Conditions.Users.IncludeUsers -join ','
            UserNames                                      = $IncludeUsers.Displayname
            ExcludeUsersIDS                                = $policy.Conditions.Users.ExcludeUsers -join ','
            ExcludeuserNames                               = $ExcludeUsers.Displayname
            Group_IDs                                      = $policy.Conditions.Users.IncludeGroups -join ','
            Groupnames                                     = $IncludeGroups.DisplayName
            ExcludeGroupIDS                                = $policy.Conditions.Users.ExcludeGroups -join ','
            ExcludeGroupsNames                             = $ExludeGroups.Displayname
            Roles_IDs                                      = $policy.Conditions.Users.IncludeRoles -join ','
            Rolenames                                      = $IncludeRoles.Displayname
            ExludeRole_IDS                                 = $policy.Conditions.Users.ExcludeRoles -join ','
            ExludeRoleNames                                = $ExcludeRoles.Displayname
            Location_IDS                                   = $policy.Conditions.Locations.Includelocations -join ','
            LocationNames                                  = $IncludeLocations
            ExcludeLocation_IDS                            = $policy.Conditions.Locations.ExcludeLocations -join ','
            ExcludeLocationNames                           = $Excludelocations
            GrantControl_BuiltinControl                    = $policy.GrantControls.BuiltinControls
            GrantControl_CustomAuthenticationFactor        = $policy.Grantcontrols.CustomAuthenticationFactors
            GrantControl_TermsOfUse                        = $policy.Grantcontrols.GrantControl.TermsOfUse
            SessionControl_Signinfrequency                 = $policy.SessionControls.SignInFrequency
            SessionControl_PersistentBrowser               = $policy.SessionControls.PersistentBrowser
            SessionControl_ApplicationEnforcedRestrictions = $policy.SessionControls.ApplicationEnforcedRestrictions
            SessionControl_CloudAppSecurity                = $policy.SessionControls.CloudAppSecurity
        }
        Clear-Variable IncludeLocations
        Clear-Variable Excludelocations
    }
    if ($ExportLocation) {
        $array | Out-File $ExportLocation
    }
    else {
        return $array
    }
}

