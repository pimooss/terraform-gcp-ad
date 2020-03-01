variable "project_id" {
  description = "Project ID for AD Domain controllers."
  type        = string
}

variable "default_region" {
  description = "Default region for resources."
  type        = string
}

variable "network_project_id" {
  description = "Project ID for network, for use with shared VPCs."
  type        = string
}

variable "network_name" {
  description = "Name of the network to create the DCs in."
  type        = string
}

variable "subnet_name" {
  description = "Name of the subnetwork to create the DCs in.."
  type        = string
}

variable "instance_tags" {
  description = "A list of tags to apply to the instance."
  type        = list(string)
  default     = []
}

variable "pdc_zone" {
  description = "Zone for primary domain controller. E.g australia-southeast1-b"
  type        = string
}

variable "sdc_zone" {
  description = "Zone for secondary domain controller. E.g australia-southeast1-c"
  type        = string
}

variable "domain" {
  description = "Fully qualified domain name. e.g fqdn.domain.name"
  type        = string
}

variable "dc_netbios_name" {
  description = "Fully qualified domain name. e.g domain"
  type        = string
}
