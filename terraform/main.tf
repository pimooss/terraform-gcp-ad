/******************************************
  Provider configuration
 *****************************************/
provider "google" {
  version      = "~> 3.6"
}
 
provider "google-beta" {
  version      = "~> 3.6"
}

# This is temporary, this should go to a parameter store or env variables...
locals {
  this-project-id = "ad-project-id"
  region          = "australia-southeast1"
  # Zones - "Primary" and "Secondary" DC in order of deployment
  pdc-zone = "australia-southeast1-b"
  sdc-zone = "australia-southeast1-c"

  # GCS & KMS settings for securely storing AD autogenerated credentials
  gcs-prefix      = "gs://ad-bucket"
  keyring         = "ad-deployment-ring"
  kms-key         = "ad-deployment-key"

  # Domain
  domain          = "fqdn.domain.name"
  dc-netbios-name = "domain"

  
  # Shared VPC related
  shared-vpc      = "shared-vpc"
  shared-vpc-project-id = "shared-vpc-project-id"
  network         = "projects/${local.shared-vpc-project-id}/global/networks/${local.shared-vpc}"
  network_url     = "https://www.googleapis.com/compute/v1/projects/${local.shared-vpc-project-id}/global/networks/${local.shared-vpc}"
  subnetwork      = "projects/${local.shared-vpc-project-id}/regions/${local.region}/subnetworks/${local.subnetwork}"
}

# Uncomment for GCS backend
# terraform {
#   backend "gcs" {
#     bucket = "tf-bucket"
#     prefix= "terraform/state"
#   }
# }

data "template_file" "windowsstartup" {
  template = file("../powershell/windows-stackdriver-setup.ps1")
}

# Todo : Create a adbucket bucket with correct kms key-ring and iam permissions

# resource "google_storage_bucket" "adbucket" {
#   name     = replace("${local.gcs-prefix}","gs://","") 
#   location = local.region
# }

resource "google_storage_bucket_object" "bootstrap1" {
  name   = "powershell/bootstrap/primary-domain-controller-step-1.ps1"
  source = "../powershell/primary-domain-controller-step-1.ps1"
  bucket = "adbucket"
}
resource "google_storage_bucket_object" "bootstrap2" {
  name   = "powershell/bootstrap/primary-domain-controller-step-2.ps1"
  source = "../powershell/primary-domain-controller-step-2.ps1"
  bucket = "adbucket"
}

resource "google_storage_bucket_object" "bootstrap_sdc1" {
  name   = "powershell/bootstrap/secondary-domain-controller-step-1.ps1"
  source = "../powershell/secondary-domain-controller-step-1.ps1"
  bucket = "adbucket"
}

resource "google_storage_bucket_object" "bootstrap_sdc2" {
  name   = "powershell/bootstrap/secondary-domain-controller-step-2.ps1"
  source = "../powershell/secondary-domain-controller-step-2.ps1"
  bucket = "adbucket"
}

resource "google_compute_instance" "dc_1" {
  project      = local.this-project-id
  name         = "ad01"
  machine_type = "n1-standard-2"
  zone         = local.pdc-zone
  tags         = ["allow-rdp", "allow-ad","allow-dns-forwarding"]

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "gce-uefi-images/windows-2019"
      size  = "50"
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = local.subnetwork
  }

  metadata = {
    windows-startup-script-ps1 = data.template_file.windowsstartup.rendered
    domain-name                = local.domain
    region                     = local.region
    keyring-region             = local.region
    keyring                    = local.keyring
    kms-key                    = local.kms-key
    gcs-prefix                 = local.gcs-prefix
    netbios-name               = local.dc-netbios-name
    project-id                 = local.this-project-id
    function                   = "pdc"
  }

  service_account {
    scopes = ["cloud-platform", "https://www.googleapis.com/auth/cloudruntimeconfig", "storage-rw"]
  }
  lifecycle {
    ignore_changes = [metadata.windows-startup-script-ps1]
  }
}

# Todo: create firewall rules in shared VPC with network tags "allow-ad" and "allow-dns-forwarding"

resource "google_compute_instance" "dc_2" {
  project      = local.this-project-id
  name         = "ad02"
  machine_type = "n1-standard-2"
  zone         = local.sdc-zone
  tags         = ["allow-rdp", "allow-ad","allow-dns-forwarding"]

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "gce-uefi-images/windows-2019"
      size  = "50"
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = local.subnetwork
  }

  metadata = {
    windows-startup-script-ps1 = data.template_file.windowsstartup.rendered
    domain-name                = local.domain
    region                     = local.region
    keyring-region             = local.region
    keyring                    = local.keyring
    kms-key                    = local.kms-key
    gcs-prefix                 = local.gcs-prefix
    netbios-name               = local.dc-netbios-name
    project-id                 = local.this-project-id
    function                   = "sdc" # secondary
    post-join-script-url       = "${local.gcs-prefix}/${google_storage_bucket_object.bootstrap_sdc2.name}"
  }

  service_account {
    scopes = ["cloud-platform", "https://www.googleapis.com/auth/cloudruntimeconfig", "storage-rw"]
  }
  lifecycle {
    ignore_changes = [metadata.windows-startup-script-ps1,metadata.post-join-script-url]
  }
  
  depends_on = [google_compute_instance.dc_1]

}

resource "google_dns_managed_zone" "forwarding" {
  provider    = google-beta
  project     = shared-vpc-project-id
  name        = replace("${local.domain}",".","-")
  dns_name    = "${local.domain}."
  description = "Terraform-managed zone."
  visibility  = "private"
  
  forwarding_config {
    target_name_servers {
      ipv4_address = [google_compute_instance.dc_1.network_interface[0].network_ip , google_compute_instance.dc_2.network_interface[0].network_ip]
    }
  }
  depends_on = [google_compute_instance.dc_1]
}

