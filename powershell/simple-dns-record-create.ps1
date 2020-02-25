# Simple DNS record creation

Param(
    [parameter(Mandatory=$true)][string] $script:zone,
    [parameter(Mandatory=$true)][string] $dns_user,
    [parameter(Mandatory=$true)][string] $dns_pwd
)

$dns_pwd_ss = $dns_pwd | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($dns_user,$dns_pwd_ss)


# Getting host info and IP configuration
$script:hostname = $($env:COMPUTERNAME).ToLower()
$script:ip = $(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress 
# Adding Record
Invoke-Command -Credential $credential -ComputerName . -ScriptBlock {
    Try {
        Return Add-DnsServerResourceRecordA -ZoneName $zone -Name $hostname -IPv4Address $ip -CreatePtr
    }
    Catch {
        Return "DNS Record creation failed [$zone - $hostname - $ip with user $dns_user]: $PSItem"
    }
}