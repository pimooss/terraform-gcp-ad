#
#  Copyright 2018 Google Inc.
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
Function Unwrap-SecureString() {
	Param(
		[System.Security.SecureString] $SecureString
	)
	Return (New-Object -TypeName System.Net.NetworkCredential -ArgumentList '', $SecureString).Password
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

Function Set-SecretManagerPassword() {
	Param(
		[Parameter(Mandatory=$True)][String] $SecretPath,
        [Parameter(Mandatory=$True)][String] $SecretData
	)
		
	$Bytes = [System.Text.Encoding]::UTF8.GetBytes($SecretData)
	$EncodedText =[Convert]::ToBase64String($Bytes)

	$secret = @{
		"payload" = @{
			"data" = $EncodedText;
		}
	}

	$requestBody = $secret | ConvertTo-Json

	$apiToken = Get-GoogleMetadata "instance/service-accounts/default/token"
	$secretUrl = 'https://secretmanager.googleapis.com/v1beta1/' + $SecretPath + ':addVersion'

	$headers = @{
		'content-type' = 'application/json'
		'Authorization' = 'Bearer '+ $apiToken.access_token
	}
	
	Try {
        Write-Host "Setting password set for $SecretPath"
		Return Invoke-RestMethod -Headers $headers -Uri $secretUrl -Method POST -Body $requestBody

	}
	Catch {
		Write-Host "Failed to set secret for $SecretPath"
		Return $Null
	}
}


Write-Host "Bootstrap script started..."

Write-Host "Installing AD features..."
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

Write-Host "Fetching metadata parameters..."
$Domain = Get-GoogleMetadata "instance/attributes/domain-name" 
$NetBiosName = Get-GoogleMetadata "instance/attributes/netbios-name"
$GcsPrefix = Get-GoogleMetadata "instance/attributes/gcs-prefix"
$Region = Get-GoogleMetadata "instance/attributes/region"
$SecretManagerSafeMode = Get-GoogleMetadata "instance/attributes/safe-mode-admin-pw"
$SecretManagerLocalAdmin = Get-GoogleMetadata "instance/attributes/local-admin-pw"
$ProjectId = Get-GoogleMetadata 'project/project-id'

Write-Host "Configuring admin credentials..."
$SafeModeAdminPassword = New-RandomPassword
$LocalAdminPassword = New-RandomPassword

Set-LocalUser Administrator -Password $LocalAdminPassword
Enable-LocalUser Administrator

Write-Host "Writing to secrets manager..."

$safeModeSecretPath = 'projects/'+$ProjectId+'/secrets/'+$SecretManagerSafeMode
$safeModeAdminPasswordUnwrap = Unwrap-SecureString $SafeModeAdminPassword 
Set-SecretManagerPassword -SecretPath $safeModeSecretPath -SecretData $safeModeAdminPasswordUnwrap

$localAdminSecretPath = 'projects/'+$ProjectId+'/secrets/'+$SecretManagerLocalAdmin
$localAdminPasswordUnwrap = Unwrap-SecureString $LocalAdminPassword 
Set-SecretManagerPassword -SecretPath $localAdminSecretPath -SecretData $localAdminPasswordUnwrap

Write-Host "Waiting for background jobs..."
Get-Job | Wait-Job

Write-Host "Creating AD forest..."

$Params = @{
	DomainName = $Domain
	DomainNetbiosName = $NetBiosName
	InstallDNS = $True
	NoRebootOnCompletion = $True
	SafeModeAdministratorPassword = $SafeModeAdminPassword
	Force = $True
}
Install-ADDSForest @Params

Write-Host "Configuring startup metadata..."
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
gcloud compute instances add-metadata "$name" --zone $zone --metadata windows-startup-script-url="$GcsPrefix/powershell/bootstrap/primary-domain-controller-step-2.ps1"

Write-Host "Restarting computer after step 1 ..."

Restart-Computer
