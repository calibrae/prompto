variable "state_passphrase" {
  type      = string
  sensitive = true
}
variable "sudo_password_hash" {
  description = "crypt(3) $6$ hash of the sandbox sudo password (tf.sh computes it; never the clear text)."
  type        = string
  sensitive   = true
}
variable "ssh_pubkey" {
  description = "Contents of sbx_ed25519.pub."
  type        = string
}
variable "libvirt_uri" {
  type    = string
  default = "qemu:///system"
}
variable "prefix" {
  description = "Guest name prefix."
  type        = string
  default     = "sbx-"
}
variable "ip_base" {
  description = "First three octets of the guest subnet. Must stay on the walled `default` network."
  type        = string
  default     = "192.168.122"
}
variable "host_offset" {
  description = "Added to every guest's last IP octet (and its MAC digits) so a parallel copy can coexist."
  type        = number
  default     = 0
}
variable "mac_prefix" {
  description = "First five MAC bytes; the last byte is the IP's last octet written as decimal digits (.11 -> :11)."
  type        = string
  default     = "52:54:00:5b:00"
}
variable "network" {
  type    = string
  default = "default"
}
variable "pool" {
  type    = string
  default = "images"
}
variable "debian_base_name" {
  type    = string
  default = "sbx-debian13-base.qcow2"
}
variable "freebsd_release" {
  type    = string
  default = "14.5-RELEASE"
}
variable "memory_cap_mb" {
  description = "If set, caps every guest's RAM (for small test copies)."
  type        = number
  default     = null
}
