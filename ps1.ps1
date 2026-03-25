# Enable-WindowsOptionalFeature -Online -FeatureName containers -All
# & 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchDaemon
# docker run -it mcr.microsoft.com/windows/servercore:ltsc2019
# Add-WindowsFeature -Name DNS -IncludeManagementTools

# Import the required module
Import-Module DnsServer

# Get all DNS zones
$zones = Get-DnsServerZone

#MDA-DC1.MDA.MIL

# Iterate through each zone
foreach ($zone in $zones) {
    Write-Output ("Zone: " + $zone.ZoneName)
    
    # Get DNS records for the zone
    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName

    # Print DNS records
    foreach ($record in $records) {
        Write-Output ("Record Name: " + $record.HostName)
        Write-Output ("Record Type: " + $record.RecordType)
        Write-Output ("Record Data: " + $record.RecordData)
        Write-Output ("------------------------")
    }
}