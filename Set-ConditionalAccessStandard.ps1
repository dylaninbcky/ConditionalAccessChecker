##Space for Custom Functions needed...
## Fout in check in 1 ip adress of meerdere
Function Set-CustomNamedLocation {
    param (
        [parameter(Mandatory = $true)]$displayname,
        [parameter(Mandatory = $true)]$ipaddresses
    )
    $Octet = '(?:0?0?[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])'
    $ipaddresses -match $Octet
    if ($ipaddresses -notlike '*,*') {
        Write-Host "$ipaddresses is probably one ip address"
        $params = @{
            "@odata.type" = "#microsoft.graph.ipNamedLocation"
            DisplayName   = $displayname
            IsTrusted     = $true
            IpRanges      = @(
                @{
                    "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                    CidrAddress   = "$ipaddresses/32"
                }
            )
        }
        Write-Host "Creating Named location $displayname" -ForegroundColor Green
        $obj = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
        return $obj
    }
    elseif ($ipaddresses -like "*,*") {
        Write-Host "$ipaddresses is probably more then one ip address seperated by a comma"
        $splitobject = ($ipaddresses.Split(','))
        Write-Host "$($ipaddresses.Split(',').Count) IP addresses recognized"
        $params = @{
            "@odata.type" = "#microsoft.graph.ipNamedLocation"
            DisplayName   = $displayname
            IsTrusted     = $true
            IpRanges      = @()
        }
        foreach ($object in $splitobject) {
            $IPRanges = @{}
            $IPRanges.Add("@odata.type" , "#microsoft.graph.iPv4CidrRange")
            $IPRanges.Add("CidrAddress", "$object/32")
            $params.IpRanges += $IPRanges
        }
        Write-Host "Creating Named location $displayname" -ForegroundColor Green
        $obj = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
        return $obj
    }
    else {
        Write-Error "No IP addresses recognized. Check input."
        exit
    }
}
    

Connect-MgGraph -Scopes `
    'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All', `
    'Directory.ReadWrite.All', 'Rolemanagement.Read.Directory', `
    'Rolemanagement.ReadWrite.Directory'

Connect-AzureAD

Write-Host "Connected to Graph api!" -ForegroundColor Green
Write-Host "Creating AzureAD security group for GeoBlock Exclude : Sys-GEOblock-Exclude"
$GeoExclude = (New-AzureADGroup -DisplayName "Sys-GEOblock-Exclude" -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet").ObjectID

Write-Host '=======================Want to create named location for trusted IPs?================================' -ForegroundColor Cyan
Write-Host 'Press 1 to create a named location'
Write-Host 'Press 2 to continue without creating a Named location for IP Addresses'
$selection = Read-Host -Prompt "Choose your selection"
switch ($selection) {
    '1' {
        $name = Read-Host -Prompt "Input Displayname for Named Location"
        $ipaddresses = Read-Host -Prompt "Input ip addresses seperated by a ,"
        if ($name -and $ipaddresses) {
            Write-Host "your selection is as follows Displayname: $name and IP Addresses: $ipaddresses"
            Set-CustomNamedLocation -displayname $name -ipaddresses $ipaddresses
        }
        else {
            Write-Host "you didnt populate the Variables for the Displayname and IP Addresses"
            Write-Host "Try again"
            $name = Read-Host -Prompt "Input Displayname for Named Location"
            $ipaddresses = Read-Host -Prompt "Input ip addresses seperated by a ,"
            Set-CustomNamedLocation -displayname $name -ipaddresses $ipaddresses
        }
    }
    '2' {
        Continue
    }
}

Write-Host '=======================Does the Client use Azure Virtual Desktop?================================' -ForegroundColor Cyan
Write-Host 'Press 1 if the Customer uses Azure Virtual Desktop' -ForegroundColor Green
Write-Host 'Press 2 if the Customer does NOT use Azure virtual desktop' -ForegroundColor Red
$selection = Read-Host -Prompt "Choose your selection"
switch ($selection) {
    '1' {
        ##Require MFA - Users
        ##Apps
        $conditions1 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
        $conditions1.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
        $conditions1.Applications.IncludeApplications = "All"

        ##Users
        $conditions1.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
        $conditions1.Users.IncludeUsers = "All"
        $conditions1.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id
        $conditions1.Users.ExcludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID

        #require MFA
        $grantcontrol1 = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
        $grantcontrol1.BuiltInControls = "Mfa"
        $grantcontrol1._Operator = "OR"

        ##Session Controls
        $SessionControls1 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
        $SessionControls1.SignInFrequency = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
        $SessionControls1.SignInFrequency.Type = 'Days'
        $SessionControls1.SignInFrequency.Value = '7'
        $SessionControls1.SignInFrequency.IsEnabled = 'True'

        Write-Host "Creating..... Require MFA - Users" -ForegroundColor Green
        New-AzureADMSConditionalAccessPolicy `
            -Displayname "Require MFA - Users (All except AVD)" `
            -State "Disabled" `
            -Conditions $conditions1 `
            -GrantControls $grantcontrol1 `
            -SessionControls $SessionControls1 


    }
    '2' {
        ##Require MFA - Users (All Except AVD)
        ##Apps
        $conditions1 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
        $conditions1.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
        $conditions1.Applications.IncludeApplications = "All"
        $conditions1.Applications.ExcludeApplications = "9cdead84-a844-4324-93f2-b2e6bb768d07"

        ##Users
        $conditions1.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
        $conditions1.Users.IncludeUsers = "All"
        $conditions1.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id
        $conditions1.Users.ExcludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID

        #require MFA
        $grantcontrol1 = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
        $grantcontrol1.BuiltInControls = "Mfa"
        $grantcontrol1._Operator = "OR"

        ##Session Controls
        $SessionControls1 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
        $SessionControls1.SignInFrequency = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
        $SessionControls1.SignInFrequency.Type = 'Days'
        $SessionControls1.SignInFrequency.Value = '7'
        $SessionControls1.SignInFrequency.IsEnabled = 'True'

        Write-Host "Creating..... Require MFA - Users (All except AVD)" -ForegroundColor Green
        New-AzureADMSConditionalAccessPolicy `
            -Displayname "Require MFA - Users (All except AVD)" `
            -State "Disabled" `
            -Conditions $conditions1 `
            -GrantControls $grantcontrol1 `
            -SessionControls $SessionControls1 


        ##Require MFA - Users (AVD)
        ##Apps
        $conditions2 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
        $conditions2.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
        $conditions2.Applications.IncludeApplications = "9cdead84-a844-4324-93f2-b2e6bb768d07"

        ##Users
        $conditions2.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
        $conditions2.Users.IncludeUsers = "All"
        $conditions2.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id
        $conditions2.Users.ExcludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID

        #require MFA
        $grantcontrol2 = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
        $grantcontrol2.BuiltInControls = "Mfa"
        $grantcontrol2._Operator = "OR"

        ##Session Controls
        $SessionControls2 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
        $SessionControls2.SignInFrequency = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
        $SessionControls2.SignInFrequency.Type = 'Days'
        $SessionControls2.SignInFrequency.Value = '1'
        $SessionControls2.SignInFrequency.IsEnabled = 'True'

        Write-Host "Creating..... Require MFA - Users (AVD)" -ForegroundColor Green
        New-AzureADMSConditionalAccessPolicy `
            -Displayname "Require MFA - Users (AVD)" `
            -State "Disabled" `
            -Conditions $conditions2 `
            -GrantControls $grantcontrol2 `
            -SessionControls $SessionControls2 
    }
}


##require MFA Admins
##Apps
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"

##Users
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID
$conditions.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id

##GrantControlset
$grantcontrol = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$grantcontrol.BuiltInControls = "Mfa"
$grantcontrol._Operator = "OR"

##Session Controls
$SessionControls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$SessionControls.SignInFrequency = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
$SessionControls.SignInFrequency.Type = 'Hours'
$SessionControls.SignInFrequency.Value = '8'
$SessionControls.SignInFrequency.IsEnabled = 'True'
$SessionControls.PersistentBrowser = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPersistentBrowser
$SessionControls.PersistentBrowser.IsEnabled = 'True'
$SessionControls.PersistentBrowser.Mode = "Never"

Write-Host "Creating..... Require MFA - Admins" -ForegroundColor Green
New-AzureADMSConditionalAccessPolicy `
    -Displayname "Require MFA - Admins" `
    -State "Disabled" `
    -Conditions $conditions `
    -GrantControls $grantcontrol `
    -SessionControls $SessionControls 

Write-Host "Setting Country lists" -ForegroundColor Green
$AllExceptEu = @(
    "XK", "ZW", "ZM", "YE", "WF", "VI", "VG", "VN", "VE", "VU", "UZ", "UM", "UY", "US", "AE", "UA", "UG", "TV", "TC", "TM", "TR", "TN",
    "TT", "TO", "TK", "TG", "TL", "TH", "TZ", "TJ", "TW", "SY", "SZ", "SJ", "SR", "SD", "LK", "SS", "GS", "ZA", "SO", "SB", "SX", "SG",
    "SL", "SC", "RS", "SN", "SA", "ST", "SM", "WS", "VC", "PM", "MF", "LC", "KN", "SH", "BL", "RW", "RU", "RE", "CG", "QA", "PR", "PN",
    "PH", "PE", "PY", "PG", "PA", "PS", "PW", "PK", "OM", "MP", "MK", "KP", "NF", "NU", "NG", "NE", "NI", "NZ", "NC", "NP", "NR", "NA",
    "MM", "MZ", "MA", "MS", "ME", "MN", "MC", "MD", "FM", "MX", "YT", "MU", "MR", "MQ", "MH", "ML", "MV", "MY", "MW", "MG", "MO", "LY",
    "LR", "LS", "LB", "LA", "KG", "KW", "KR", "KI", "KE", "KZ", "JO", "JE", "JP", "JM", "IL", "IM", "IQ", "IR", "ID", "IN", "IS", "HK",
    "HN", "VA", "HM", "HT", "GY", "GW", "GN", "GG", "GT", "GU", "GP", "GD", "GL", "GI", "GH", "GE", "GM", "GA", "TF", "PF", "GF", "FJ",
    "FO", "FK", "ET", "ER", "GQ", "SV", "EH", "EG", "EC", "DO", "DM", "DJ", "CD", "CW", "CU", "CI", "CR", "CK", "KM", "CO", "CC", "CX",
    "CN", "CL", "TD", "CF", "KY", "CA", "CM", "KH", "CV", "BI", "BF", "BN", "IO", "BR", "BV", "BW", "BA", "BQ", "BO", "BT", "BM", "BJ",
    "BZ", "BY", "BB", "BD", "BH", "BS", "AZ", "AU", "AW", "AM", "AR", "AG", "AQ", "AI", "AO", "AD", "AS", "DZ", "AL", "AX", "AF", "SZ"
)

$AllExceptNL = @(
    "XK", "ZW", "ZM", "YE", "WF", "VI", "VG", "VN", "VE", "VU", "UZ", "UM", "UY", "US", "GB", "AE", "UA", "UG", "TV", "TC", "TM", "TR",
    "TN", "TT", "TO", "TK", "TG", "TL", "TH", "TZ", "TJ", "TW", "SY", "CH", "SE", "SZ", "SJ", "SR", "SD", "LK", "ES", "SS", "GS", "ZA",
    "SO", "SB", "SI", "SK", "SX", "SG", "SL", "SC", "RS", "SN", "SA", "ST", "SM", "WS", "VC", "PM", "MF", "LC", "KN", "SH", "BL", "RW",
    "RU", "RO", "RE", "CG", "QA", "PR", "PT", "PL", "PN", "PH", "PE", "PY", "PG", "PA", "PS", "PW", "PK", "OM", "NO", "MP", "MK", "KP",
    "NF", "NU", "NG", "NE", "NI", "NZ", "NC", "NP", "NR", "NA", "MM", "MZ", "MA", "MS", "ME", "MN", "MC", "MD", "FM", "MX", "YT", "MU",
    "MR", "MQ", "MH", "MT", "ML", "MV", "MY", "MW", "MG", "MO", "LU", "LT", "LI", "LY", "LR", "LS", "LB", "LV", "LA", "KG", "KW", "KR",
    "KI", "KE", "KZ", "JO", "JE", "JP", "JM", "IT", "IL", "IM", "IE", "IQ", "IR", "ID", "IN", "IS", "HU", "HK", "HN", "VA", "HM", "HT",
    "GY", "GW", "GN", "GG", "GT", "GU", "GP", "GD", "GL", "GR", "GI", "GH", "DE", "GE", "GM", "GA", "TF", "PF", "GF", "FR", "FI", "FJ",
    "FO", "FK", "ET", "EE", "ER", "GQ", "SV", "EH", "EG", "EC", "DO", "DM", "DJ", "DK", "CD", "CZ", "CY", "CW", "CU", "HR", "CI", "CR",
    "CK", "KM", "CO", "CC", "CX", "CN", "CL", "TD", "CF", "KY", "CA", "CM", "KH", "CV", "BI", "BF", "BG", "BN", "IO", "BR", "BV", "BW",
    "BA", "BQ", "BO", "BT", "BM", "BJ", "BZ", "BE", "BY", "BB", "BD", "BH", "BS", "AZ", "AT", "AU", "AW", "AM", "AR", "AG", "AQ", "AI",
    "AO", "AD", "AS", "DZ", "AL", "AX", "AF"
)

Write-Host "Creating Named locations for GEO Block" -ForegroundColor Green
##AllExceptEU
$params = @{
    "@odata.type"                     = "Microsoft.Graph.CountryNamedLocation"
    Displayname                       = "Geo - All except EU"
    CountriesAndRegions               = $AllExceptEu
    IncludeUnknownCountriesAndRegions = $true
}
$ALLExceptEuropeID = (New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params).Id

##AllExceptNL
$params = @{
    "@odata.type"                     = "Microsoft.Graph.CountryNamedLocation"
    Displayname                       = "Geo - All except NL"
    CountriesAndRegions               = $AllExceptNL
    IncludeUnknownCountriesAndRegions = $true
}
$ALLExceptNLID = (New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params).Id


##GEO Block - Admins buiten NL
##Apps
$conditions3 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions3.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions3.Applications.IncludeApplications = "All"

##Users
$conditions3.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions3.Users.IncludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID
$conditions3.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id
##locations
$conditions3.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions3.Locations.IncludeLocations = $ALLExceptNLID

##GrantControlset
$grantcontrol3 = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$grantcontrol3.BuiltInControls = "Block"
$grantcontrol3._Operator = "OR"

Write-Host "Creating..... Geo Block - Admins outside NL" -ForegroundColor Green
New-AzureADMSConditionalAccessPolicy `
    -Displayname "Geo Block - Admins outside NL" `
    -State "Disabled" `
    -Conditions $conditions3 `
    -GrantControls $grantcontrol3





##GEO Block - Users outside EU
##Apps
$conditions4 = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions4.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions4.Applications.IncludeApplications = "All"

##Users
$conditions4.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions4.Users.IncludeUsers = "All"
$conditions4.Users.ExcludeUsers = (Get-MgUser | Where { $_.Displayname -like "On-Premises Directory*" }).Id
$conditions4.Users.ExcludeGroups = $GeoExclude
$conditions4.Users.ExcludeRoles = (Get-MgDirectoryRole | Where { $_.Displayname -eq 'Global Administrator' }).RoleTemplateID
##locations
$conditions4.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions4.Locations.IncludeLocations = $ALLExceptEuropeID

##GrantControlset
$grantcontrol4 = New-Object -Typename Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$grantcontrol4.BuiltInControls = "Block"
$grantcontrol4._Operator = "OR"

Write-Host "Creating..... Geo Block - Users outside EU" -ForegroundColor Green
New-AzureADMSConditionalAccessPolicy `
    -Displayname "Geo Block - Users outside EU" `
    -State "Disabled" `
    -Conditions $conditions4 `
    -GrantControls $grantcontrol4