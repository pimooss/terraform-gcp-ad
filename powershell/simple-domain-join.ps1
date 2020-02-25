# Simple domain join script

Param(
    [parameter(Mandatory=$true)][string] $domain_fqdn,    
    [parameter(Mandatory=$true)][string] $domain_join_user,
    [parameter(Mandatory=$true)][string] $domain_join_pwd
)

$domain_join_pwd_ss = $domain_join_pwd | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($domain_join_user,$domain_join_pwd_ss)
Try {
    Return Add-computer -DomainName $domain_fqdn -Credential $credential -Restart
}
Catch {
    Return "Domain join failed [$domain_fqdn with user $domain_join_user]: $PSItem"
}