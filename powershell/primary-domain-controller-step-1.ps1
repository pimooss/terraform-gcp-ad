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

Import-Module GoogleCloud

##### Helper Functions #####

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
        Write-Output "Setting password set for $SecretPath"
		Return Invoke-RestMethod -Headers $headers -Uri $secretUrl -Method POST -Body $requestBody

	}
	Catch {
		Write-Output "Failed to set secret for $SecretPath"
		Return $Null
	}
}

##### Helper Functions #####

##### Bootstrap Functions #####

#TODO: Convert to powershell DSC
Function Install-ADDSFeature() {
	Write-Output ""
	Write-Output "Installing AD features..."
	Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
}

Function Initialize-ADEnvironment() {
	Install-ADDSFeature
	
	Write-Output ""
	Write-Output "Fetching metadata parameters..."
	$script:Domain = Get-GoogleMetadata -Path "instance/attributes/domain-name" 
	$script:NetBiosName = Get-GoogleMetadata -Path "instance/attributes/netbios-name"
	$script:GcsPrefix = Get-GoogleMetadata -Path "instance/attributes/gcs-prefix"
	$script:Region = Get-GoogleMetadata -Path "instance/attributes/region"
	$script:SecretManagerSafeMode = Get-GoogleMetadata -Path "instance/attributes/safe-mode-admin-pw"
	$script:SecretManagerLocalAdmin = Get-GoogleMetadata -Path "instance/attributes/local-admin-pw"
	$script:ProjectId = Get-GoogleMetadata -Path 'project/project-id'
}

Function Initialize-ADForest() {
	Write-Output ""
	Write-Output "Creating AD forest..."

	$Params = @{
		DomainName = $Domain
		DomainNetbiosName = $NetBiosName
		InstallDNS = $True
		NoRebootOnCompletion = $True
		SafeModeAdministratorPassword = $SafeModeAdminPassword
		Force = $True
	}

	Install-ADDSForest @Params
}

# Generates AD Safemode password and set new pw for local admin SID-500 account
Function Initialize-localPasswords() {
	Write-Output ""
	Write-Output "Configuring admin credentials..."
	$script:SafeModeAdminPassword = New-RandomPassword
	$script:LocalAdminPassword = New-RandomPassword

	Set-LocalUser Administrator -Password $LocalAdminPassword
	Enable-LocalUser Administrator
}

# Stores generated runtime passwords in google secrets manager
Function Initialize-ADPasswords-SecretsManager() {
	Write-Output ""
	Write-Output "Writing to secrets manager..."

	$safeModeSecretPath = 'projects/'+$ProjectId+'/secrets/'+$SecretManagerSafeMode
	$safeModeAdminPasswordUnwrap = Unwrap-SecureString $SafeModeAdminPassword 
	Set-SecretManagerPassword -SecretPath $safeModeSecretPath -SecretData $safeModeAdminPasswordUnwrap

	$localAdminSecretPath = 'projects/'+$ProjectId+'/secrets/'+$SecretManagerLocalAdmin
	$localAdminPasswordUnwrap = Unwrap-SecureString $LocalAdminPassword 
	Set-SecretManagerPassword -SecretPath $localAdminSecretPath -SecretData $localAdminPasswordUnwrap
}

Function Set-Bootstrap-Script() {
	Write-Output ""
	Write-Output "Configuring startup metadata..."
	$name = Get-GoogleMetadata -Path "instance/name"
	$zone = Get-GoogleMetadata -Path "instance/zone"
	$metadata = @{"windows-startup-script-url" = "$GcsPrefix/powershell/bootstrap/primary-domain-controller-step-2.ps1"}
	
	Set-GceInstance -Name $name -Zone $zone -AddMetadata $metadata
}

Function __main__() {
	Write-Output ""
	Write-Output ">>> Bootstrap script started... <<<"
	Initialize-ADEnvironment
	Initialize-localPasswords
	Initialize-ADPasswords-SecretsManager
	Initialize-ADForest

	Write-Output ""
	Write-Output ">>> Waiting for background jobs... <<<"
	Get-Job | Wait-Job

	Write-Output ""
	Write-Output ">>> Setting instance meta for post install/second bootstrap script... <<<"
	Set-Bootstrap-Script

	Write-Output ""
	Write-Output ">>> Restarting computer to complete bootstrap script... <<<"
	# final reboot to finish installing AD features
	Restart-Computer
}
# Script enters here
__main__

##### Bootstrap Functions #####
