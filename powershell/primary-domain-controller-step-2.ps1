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

Write-Host "Configuring NTP..."
# use google internal time server
w32tm /config /manualpeerlist:"metadata.google.internal" /syncfromflags:manual /reliable:yes /update

# poll domain controller until it appears ready
Do {
  Try {
    $test = Get-ADDomain
  }
  Catch {
      Write-Host "Waiting for DC to become available..."
      Sleep 15
  }
}
Until ($test)


Write-Host "Configuring startup metadata..."
# remove startup script from metadata to prevent rerun on reboot
$name = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/name
$zone = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/zone
gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url

Write-Host "Signaling completion..."

Write-Host "Step 2 completed"
