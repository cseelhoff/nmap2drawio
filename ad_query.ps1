# =============================================
# AD Enumeration with Group Membership (User-focused)
# Uses explicit credentials + DirectorySearcher
# =============================================

$DC = "172.17.2.6"   # Your domain controller IP or hostname

# Get credentials once
$creds = Get-Credential -Message "Enter domain credentials"

# Bind to domain with credentials
$domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC", $creds.UserName, $creds.GetNetworkCredential().Password)

$searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
$searcher.PageSize = 1000

# Filter: Only users and computers (you can add groups/OUs back if needed)
$searcher.Filter = "(|(objectCategory=person)(objectCategory=computer))"

# Load the important properties + memberOf for group membership
$searcher.PropertiesToLoad.AddRange(@(
    "name",
    "samAccountName",
    "objectClass",
    "distinguishedName",
    "userPrincipalName",
    "enabled",
    "lastLogonTimestamp",
    "memberOf"          # ← This gives us the list of groups
))

Write-Output "Querying AD with explicit credentials...`n"

$results = $searcher.FindAll()

$adObjects = [System.Collections.ArrayList[PSCustomObject]]::new()

foreach ($result in $results) {
    $p = $result.Properties

    $type = if ($p["objectclass"] -contains "computer") { "Computer" }
            elseif ($p["objectclass"] -contains "user" -or $p["objectclass"] -contains "person") { "User" }
            else { "Other" }

    # Convert lastLogonTimestamp
    $lastLogon = if ($p["lastlogontimestamp"].Count -gt 0) {
        [DateTime]::FromFileTime([long]$p["lastlogontimestamp"][0]).ToString("yyyy-MM-dd HH:mm")
    } else { "Never" }

    # Get clean list of group names from memberOf (DNs)
    $groups = @()
    if ($p["memberof"].Count -gt 0) {
        $groups = $p["memberof"] | ForEach-Object {
            if ($_ -match 'CN=([^,]+)') { $matches[1] } else { $_ }
        } | Sort-Object
    }

    $obj = [PSCustomObject]@{
        Type              = $type
        Name              = if ($p["name"].Count -gt 0) { [string]$p["name"][0] } else { "" }
        SamAccountName    = if ($p["samaccountname"].Count -gt 0) { [string]$p["samaccountname"][0] } else { "" }
        UserPrincipalName = if ($p["userprincipalname"].Count -gt 0) { [string]$p["userprincipalname"][0] } else { "" }
        Enabled           = if ($p["enabled"].Count -gt 0) { $p["enabled"][0] } else { $null }
        LastLogon         = $lastLogon
        DistinguishedName = if ($p["distinguishedname"].Count -gt 0) { [string]$p["distinguishedname"][0] } else { "" }
        GroupMembership   = $groups
    }

    $null = $adObjects.Add($obj)
}

# === Output Options ===

# 1. Pretty console output (good for quick review)
$adObjects | Sort-Object Type, Name | Format-Table Type, Name, SamAccountName, GroupMembership -AutoSize

# 2. Export to JSON (recommended for further processing)
$adObjects | ConvertTo-Json -Depth 4 | Out-File "AD_Users_With_Groups.json" -Encoding UTF8

# 3. Open in GridView
$adObjects | Out-GridView -Title "AD Users & Computers with Group Membership"

Write-Output "`nExport completed: AD_Users_With_Groups.json"
Write-Output "Total objects found: $($adObjects.Count)"
