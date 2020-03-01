# This is temporary, this should go to a parameter store or env variables...
locals {
  this-project-id = var.project_id
  region          = var.default_region
  # Zones - "Primary" and "Secondary" DC in order of deployment
  pdc-zone = var.pdc_zone
  sdc-zone = var.sdc_zone

  gcs-prefix = "gs://${google_storage_bucket.ad_bootstrap_bucket.name}"

  # Domain
  domain          = var.domain
  dc-netbios-name = var.dc_netbios_name

  # Shared VPC related
  subnetwork = "projects/${var.network_project_id}/regions/${local.region}/subnetworks/${var.subnet_name}"
}

resource "random_id" "suffix" {
  byte_length = 2
}

/*************************************************
  Service account
*************************************************/

resource "google_service_account" "ad_service_account" {
  project      = var.project_id
  account_id   = format("%s-%s", "ad-sa", random_id.suffix.hex)
  display_name = "Service Account ${format("%s-%s", "ad-sa", random_id.suffix.hex)}"
}

resource "google_service_account_iam_member" "service_account_user" {
  service_account_id = google_service_account.ad_service_account.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.ad_service_account.email}"
}

/*************************************************
  Setup GCS
*************************************************/

resource "google_storage_bucket" "ad_bootstrap_bucket" {
  project            = var.project_id
  name               = format("%s-%s", "ad-bootstrap", random_id.suffix.hex)
  location           = var.default_region
  bucket_policy_only = true
  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_iam_member" "object_admin" {
  bucket = google_storage_bucket.ad_bootstrap_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.ad_service_account.email}"
}

resource "google_storage_bucket_object" "bootstrap1" {
  name   = "powershell/bootstrap/primary-domain-controller-step-1.ps1"
  source = "${path.module}/powershell/primary-domain-controller-step-1.ps1"
  bucket = google_storage_bucket.ad_bootstrap_bucket.name
}
resource "google_storage_bucket_object" "bootstrap2" {
  name   = "powershell/bootstrap/primary-domain-controller-step-2.ps1"
  source = "${path.module}/powershell/primary-domain-controller-step-2.ps1"
  bucket = google_storage_bucket.ad_bootstrap_bucket.name
}

resource "google_storage_bucket_object" "bootstrap_sdc1" {
  name   = "powershell/bootstrap/secondary-domain-controller-step-1.ps1"
  source = "${path.module}/powershell/secondary-domain-controller-step-1.ps1"
  bucket = google_storage_bucket.ad_bootstrap_bucket.name
}

resource "google_storage_bucket_object" "bootstrap_sdc2" {
  name   = "powershell/bootstrap/secondary-domain-controller-step-2.ps1"
  source = "${path.module}/powershell/secondary-domain-controller-step-2.ps1"
  bucket = google_storage_bucket.ad_bootstrap_bucket.name
}

/*************************************************
  Setup secret manager
*************************************************/

resource "google_secret_manager_secret" "safe_mode_admin_pw" {
  provider  = google-beta
  project   = var.project_id
  secret_id = "safe-mode-admin-pw"

  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret" "local_admin_pw" {
  provider  = google-beta
  project   = var.project_id
  secret_id = "local-admin-pw"

  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_iam_member" "secret_admin_safe_mode_pw" {
  provider  = google-beta
  project   = var.project_id
  secret_id = google_secret_manager_secret.safe_mode_admin_pw.secret_id
  role      = "roles/secretmanager.admin"
  member    = "serviceAccount:${google_service_account.ad_service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "secret_admin_local_admin_pw" {
  provider  = google-beta
  project   = var.project_id
  secret_id = google_secret_manager_secret.local_admin_pw.secret_id
  role      = "roles/secretmanager.admin"
  member    = "serviceAccount:${google_service_account.ad_service_account.email}"
}


/*************************************************
  Instance Config
*************************************************/

data "template_file" "windowsstartup" {
  template = file("${path.module}/powershell/windows-stackdriver-setup.ps1")
}

resource "google_project_iam_custom_role" "set_compute_metadata" {
  project     = var.project_id
  role_id     = "setComputeMetadata"
  title       = "Permission to get instances and set instances."
  description = "Permission to get instances and set instances."
  permissions = [
    "compute.instances.setMetadata",
    "compute.instances.get"
  ]
}

resource "google_compute_instance" "dc_1" {
  project      = local.this-project-id
  name         = "ad01"
  machine_type = "n1-standard-2"
  zone         = local.pdc-zone
  tags         = var.instance_tags

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
    safe-mode-admin-pw         = google_secret_manager_secret.safe_mode_admin_pw.secret_id
    local-admin-pw             = google_secret_manager_secret.local_admin_pw.secret_id
    gcs-prefix                 = local.gcs-prefix
    netbios-name               = local.dc-netbios-name
    project-id                 = local.this-project-id
    function                   = "pdc"
  }

  service_account {
    email  = google_service_account.ad_service_account.email
    scopes = ["cloud-platform", "https://www.googleapis.com/auth/cloudruntimeconfig", "storage-rw"]
  }
  lifecycle {
    ignore_changes = [metadata.windows-startup-script-ps1]
  }
}

resource "google_compute_instance_iam_member" "dc1_set_compute_metadata" {
  project       = var.project_id
  zone          = local.pdc-zone
  instance_name = google_compute_instance.dc_1.name
  role          = "projects/${var.project_id}/roles/${google_project_iam_custom_role.set_compute_metadata.role_id}"
  member        = "serviceAccount:${google_service_account.ad_service_account.email}"
}

resource "google_compute_instance" "dc_2" {
  project      = local.this-project-id
  name         = "ad02"
  machine_type = "n1-standard-2"
  zone         = local.sdc-zone
  tags         = var.instance_tags

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
    safe-mode-admin-pw         = google_secret_manager_secret.safe_mode_admin_pw.secret_id
    local-admin-pw             = google_secret_manager_secret.local_admin_pw.secret_id
    gcs-prefix                 = local.gcs-prefix
    netbios-name               = local.dc-netbios-name
    project-id                 = local.this-project-id
    function                   = "sdc" # secondary
    post-join-script-url       = "${local.gcs-prefix}/${google_storage_bucket_object.bootstrap_sdc2.name}"
  }

  service_account {
    email  = google_service_account.ad_service_account.email
    scopes = ["cloud-platform", "https://www.googleapis.com/auth/cloudruntimeconfig", "storage-rw"]
  }
  lifecycle {
    ignore_changes = [metadata.windows-startup-script-ps1, metadata.post-join-script-url]
  }
  depends_on = [google_compute_instance.dc_1]
}

resource "google_compute_instance_iam_member" "dc2_set_compute_metadata" {
  project       = var.project_id
  zone          = local.sdc-zone
  instance_name = google_compute_instance.dc_2.name
  role          = "projects/${var.project_id}/roles/${google_project_iam_custom_role.set_compute_metadata.role_id}"
  member        = "serviceAccount:${google_service_account.ad_service_account.email}"
}

resource "google_dns_managed_zone" "forwarding" {
  provider    = google-beta
  project     = var.network_project_id
  name        = replace("${local.domain}", ".", "-")
  dns_name    = "${local.domain}."
  description = "Terraform-managed zone."
  visibility  = "private"

  forwarding_config {
    target_name_servers {
      ipv4_address = google_compute_instance.dc_1.network_interface[0].network_ip
    }
    target_name_servers {
      ipv4_address = google_compute_instance.dc_2.network_interface[0].network_ip
    }
  }
  depends_on = [google_compute_instance.dc_1]
}

