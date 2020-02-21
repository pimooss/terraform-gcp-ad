#
#  Copyright 2019 Google Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

Function Unwrap-SecureString() {
    Param(
        [System.Security.SecureString] $SecureString
    )
    Return (New-Object -TypeName System.Net.NetworkCredential -ArgumentList '', $SecureString).Password
}

Function New-RandomString {
    Param(
        [int] $Length = 10,
        [char[]] $AllowedChars = $Null
    )
    If ($AllowedChars -eq $Null) {
        (,(33,126)) | % { For ($a=$_[0]; $a -le $_[1]; $a++) { $AllowedChars += ,[char][byte]$a } }
    }
    For ($i=1; $i -le $Length; $i++) {
        $Temp += ( $AllowedChars | Get-Random )
    }
    Return $Temp
}

Function New-RandomPassword() {
	Param(
		[int] $Length = 16,
		[char[]] $AllowedChars = $Null
	)
	Return New-RandomString -Length $Length -AllowedChars $AllowedChars | ConvertTo-SecureString -AsPlainText -Force
}

Function Get-GoogleMetadata() {
    Param (
    [Parameter(Mandatory=$True)][String] $Path
    )
    Try {
        Return Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/$Path
    }
    Catch {
        Return $Null
    }
}

Write-Host "Bootstrap script started..."

$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"

Write-Host "Adding AD powershell tools..."
Add-WindowsFeature RSAT-AD-PowerShell

$ProjectId = Get-GoogleMetadata "/instance/attributes/project-id"

Write-Host "Configuring local admin..."
# startup script runs as local system which cannot join domain
# so do the join as local administrator using random password
$LocalAdminPassword = New-RandomPassword
Set-LocalUser Administrator -Password $LocalAdminPassword
Enable-LocalUser Administrator

$LocalAdminCredentials = New-Object `
    -TypeName System.Management.Automation.PSCredential `
    -ArgumentList "\Administrator",$LocalAdminPassword

Invoke-Command -Credential $LocalAdminCredentials -ComputerName . -ScriptBlock {

    Write-Host "Getting job metadata..."
    $Domain = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/domain-name
    $NetBiosName = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/netbios-name
    $KmsKey = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/kms-key
    $KmsRegion = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/keyring-region
    $Region = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/region
    $Keyring = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/keyring
    $GcsPrefix = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/gcs-prefix

    Write-Host "Waiting on domain [$Domain] to be ready"
    $TestConnection = Test-NetConnection $Domain
    While (!($TestConnection.PingSucceeded)) {
        Write-Host (Get-Date -Format 'HH:mm:ss') ": [$env:COMPUTERNAME] Waiting for connectivity to [$Domain]"
        Sleep -Seconds 5
        Clear-DnsClientCache -Confirm:$false
        $TestConnection = Test-NetConnection $Domain
    }

    Write-Host "Fetching admin credentials..."

    # fetch domain admin credentials
    If ($GcsPrefix.EndsWith("/")) {
    $GcsPrefix = $GcsPrefix -Replace ".$"
    }
    $TempFile = New-TemporaryFile

    # invoke-command sees gsutil output as an error so redirect stderr to stdout and stringify to suppress
    gsutil cp $GcsPrefix/output/domain-admin-password.bin $TempFile.FullName 2>&1 | %{ "$_" }

    $DomainAdminPassword = $(gcloud kms decrypt --key $KmsKey --location $KmsRegion --keyring $Keyring --ciphertext-file $TempFile.FullName --plaintext-file - | ConvertTo-SecureString -AsPlainText -Force)

    Remove-Item $TempFile.FullName
    Write-Host "Domain is $Domain"

    $DomainAdminCredentials = New-Object `
            -TypeName System.Management.Automation.PSCredential `
            -ArgumentList "$Domain\Administrator", $DomainAdminPassword

    Write-Host "Joining domain... using credential $($DomainAdminCredentials.UserName)"
    Add-Computer -DomainName $Domain -Credential $DomainAdminCredentials

}

Add-Type -AssemblyName System.Web
$PostJoinScriptUrl = [System.Web.HttpUtility]::UrlDecode($(Get-GoogleMetadata "instance/attributes/post-join-script-url"))

If ($PostJoinScriptUrl) {

	Write-Host "Configuring startup metadata for post-join script..."
	# set post join url as startup script then restart
	$name = Get-GoogleMetadata "instance/name"
	$zone = Get-GoogleMetadata "instance/zone"
	gcloud compute instances add-metadata "$name" --zone $zone --metadata "windows-startup-script-url=$PostJoinScriptUrl"

	Write-Host "Restarting..."
	Restart-Computer

}
Else {

	Write-Host "Configuring startup metadata..."
        # remove startup script from metadata to prevent rerun on reboot
        $name = Get-GoogleMetadata "instance/name"
        $zone = Get-GoogleMetadata "instance/zone"
        gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url

}