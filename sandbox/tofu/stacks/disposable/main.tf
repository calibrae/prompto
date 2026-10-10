# Disposable stack: sbx-core, sbx-t1, sbx-t2, sbx-bsd. Tear down and rebuild
# freely. Base images come from the persistent stack (or the pool) by name.

variable "freebsd_base_override" {
  type    = string
  default = null
}
variable "guests_enabled" {
  type    = set(string)
  default = ["core", "t1", "t2", "bsd"]
}

locals {
  freebsd_base_name = coalesce(var.freebsd_base_override, "sbx-freebsd-${split("-", var.freebsd_release)[0]}-base.qcow2")

  guests = {
    core = { name = "core", vcpu = 4, mem = 4096, disk = 30, os = "debian", sudo = "nopasswd", last = 10 }
    t1   = { name = "t1", vcpu = 1, mem = 1024, disk = 10, os = "debian", sudo = "nopasswd", last = 11 }
    t2   = { name = "t2", vcpu = 1, mem = 1024, disk = 10, os = "debian", sudo = "password", last = 12 }
    bsd  = { name = "bsd", vcpu = 1, mem = 1024, disk = 10, os = "freebsd", sudo = "password", last = 13 }
  }
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
}

output "guests" {
  value = { for k, m in module.guest : k => { name = m.name, ip = m.ip, mac = m.mac } }
}
