# Run on the NON-DOMAIN-JOINED workstation to allow PSRemoting to a domain-joined machine

$creds = Get-Credential -Message "Enter domain credentials (DOMAIN\Username)"
# Step 1: Add the remote machine to TrustedHosts (replace with actual hostname or IP)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "172.17.2.6"

Set-Item WSMan:\localhost\Client\TrustedHosts -Value "172.17.2.6"
$cimSession = New-CimSession -ComputerName '172.17.2.6'
$records = Get-CimInstance -CimSession $cimSession -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_AType" 
$records | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties | ConvertTo-Json -Depth 1 | Out-File "dns_a.json"
Get-Content .\dns_a.json | convertfrom-json | Out-GridView
