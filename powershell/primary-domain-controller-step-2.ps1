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

Function Get-RuntimeConfigWaiter {
	Param(
		[Parameter(Mandatory=$True)][String] $ConfigPath,
		[Parameter(Mandatory=$True)][String] $Waiter
	)

	$Auth = $(gcloud auth print-access-token)

	$Url = "https://runtimeconfig.googleapis.com/v1beta1/$ConfigPath/waiters/$Waiter"
	$Headers = @{
	Authorization = "Bearer " + $Auth
	}
	$Params = @{
	Method = "GET"
	Headers = $Headers
	Uri = $Url
	}

	Return Invoke-RestMethod @Params
}

##### Helper Functions #####

##### Bootstrap Functions #####

Function Set-GoogleNTPServer() {
	Write-Output ""
	Write-Output "Configuring NTP..."
	# use google internal time server
	w32tm /config /manualpeerlist:"metadata.google.internal" /syncfromflags:manual /reliable:yes /update

	$attempts = 0
	$maxAttempts = 5
	# poll domain controller until it appears ready using exponential backoff
	Do {
		Try {
			$test = Get-ADDomain
		}
		Catch {
			$attempts++
			$retryDelaySeconds = [math]::Pow(2,$attempts)
			Write-Output "Waiting for DC to become available. Retrying in $retryDelaySeconds seconds"
			Start-Sleep -Seconds $retryDelaySeconds
		}
	}
	Until ($test)
}

Function Set-Bootstrap-Script() {
	# remove startup script from metadata to prevent rerun on reboot
	$baseURI = "http://169.254.169.254/computeMetadata/v1"
	$MetadataHeader = @{"Metadata-Flavor" = "Google"}

	$name = Invoke-RestMethod -Headers $MetadataHeader -Uri "$baseURI/instance/name"
	$zone = Invoke-RestMethod -Headers $MetadataHeader -Uri "$baseURI/instance/zone"
	$metadataKey = "windows-startup-script-url"

	Set-GceInstance -Name $name -Zone $zone -RemoveMetadata $metadataKey
}

Function __main__() {
	Write-Output ""
	Write-Output ">>> Bootstrap script started... <<<"
	Set-GoogleNTPServer

	Write-Output ""
	Write-Output ">>> Configuring startup metadata... <<<"
	Set-Bootstrap-Script

	Write-Output ""
	Write-Output ">>> Step 2 completed... <<<"
}
# Script enters here
__main__

##### Bootstrap Functions #####
