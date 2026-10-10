# Persistent stack: sbx-dev (the dev agent's workstation) and the base images
# every guest overlays. Apply this first; the disposable stack consumes the
# base volumes by name.

variable "manage_base" {
  description = "Create the base image volumes (Debian from the cloud URL, FreeBSD via fetch-freebsd-base.sh). false = they already exist in the pool."
  type        = bool
  default     = true
}
variable "debian_base_url" {
  type    = string
  default = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
}
variable "freebsd_cache_dir" {
  type    = string
  default = "~/sandbox/cache"
}
variable "guests_enabled" {
  type    = set(string)
  default = ["dev"]
}

locals {
  freebsd_base_name = "sbx-freebsd-${split("-", var.freebsd_release)[0]}-base.qcow2"
  freebsd_cache     = "${var.freebsd_cache_dir}/${local.freebsd_base_name}"

  #                 vcpu  ram   disk os      sudo      ip-last
  guests = {
    dev = { name = "dev", vcpu = 3, mem = 3072, disk = 30, os = "debian", sudo = "nopasswd", last = 20 }
  }
}

resource "libvirt_volume" "debian_base" {
  count  = var.manage_base ? 1 : 0
  name   = var.debian_base_name
  pool   = var.pool
  format = "qcow2"
  source = var.debian_base_url
}

resource "terraform_data" "freebsd_fetch" {
  count = var.manage_base ? 1 : 0
  input = { release = var.freebsd_release, out = pathexpand(local.freebsd_cache) }
  provisioner "local-exec" {
    command = "${path.module}/../../scripts/fetch-freebsd-base.sh '${self.input.release}' '${self.input.out}'"
  }
}

resource "libvirt_volume" "freebsd_base" {
  count      = var.manage_base ? 1 : 0
  name       = local.freebsd_base_name
  pool       = var.pool
  format     = "qcow2"
  source     = pathexpand(local.freebsd_cache)
  depends_on = [terraform_data.freebsd_fetch]
}

module "guest" {
  source   = "../../modules/guest"
  for_each = { for k, v in local.guests : k => v if contains(var.guests_enabled, k) }

  name               = "${var.prefix}${each.value.name}"
  vcpu               = each.value.vcpu
  memory_mb          = var.memory_cap_mb == null ? each.value.mem : min(each.value.mem, var.memory_cap_mb)
  disk_gb            = each.value.disk
  os_kind            = each.value.os
  sudo_mode          = each.value.sudo
  ip                 = "${var.ip_base}.${each.value.last + var.host_offset}"
  mac                = "${var.mac_prefix}:${format("%02d", each.value.last + var.host_offset)}"
  pool               = var.pool
  network            = var.network
  libvirt_uri        = var.libvirt_uri
  base_volume_name   = each.value.os == "debian" ? var.debian_base_name : local.freebsd_base_name
  base_volume_pool   = var.pool
  ssh_pubkey         = var.ssh_pubkey
  sudo_password_hash = var.sudo_password_hash

  depends_on = [libvirt_volume.debian_base, libvirt_volume.freebsd_base]
}

output "guests" {
  value = { for k, m in module.guest : k => { name = m.name, ip = m.ip, mac = m.mac } }
}
