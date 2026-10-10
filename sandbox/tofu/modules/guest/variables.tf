variable "name" { type = string }
variable "vcpu" { type = number }
variable "memory_mb" { type = number }
variable "disk_gb" { type = number }
variable "os_kind" {
  type = string
  validation {
    condition     = contains(["debian", "freebsd"], var.os_kind)
    error_message = "os_kind must be debian or freebsd."
  }
}
variable "sudo_mode" {
  type = string
  validation {
    condition     = contains(["nopasswd", "password"], var.sudo_mode)
    error_message = "sudo_mode must be nopasswd or password."
  }
}
variable "ip" { type = string }
variable "mac" { type = string }
variable "pool" { type = string }
variable "network" { type = string }
variable "libvirt_uri" { type = string }
variable "base_volume_name" { type = string }
variable "base_volume_pool" { type = string }
variable "ssh_pubkey" { type = string }
variable "sudo_password_hash" {
  type      = string
  sensitive = true
}
variable "manage_dhcp" {
  type    = bool
  default = true
}
