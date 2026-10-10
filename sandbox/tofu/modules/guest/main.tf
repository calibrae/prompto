locals {
  freebsd   = var.os_kind == "freebsd"
  sudo_line = var.sudo_mode == "nopasswd" ? "ALL=(ALL) NOPASSWD:ALL" : "ALL=(ALL) ALL"
}

# DHCP reservation, same mechanism as up.sh (virsh net-update on the existing
# network). The provider's libvirt_network would take over the whole `default`
# network (and replace it), so the reservation is a scoped local-exec instead.
# Needs virsh on the machine running tofu. Idempotent; removed on destroy.
resource "terraform_data" "dhcp" {
  count = var.manage_dhcp ? 1 : 0
  input = {
    uri  = var.libvirt_uri
    net  = var.network
    name = var.name
    mac  = var.mac
    ip   = var.ip
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      if virsh -c '${self.input.uri}' net-dumpxml '${self.input.net}' | grep -qi "mac='${self.input.mac}'"; then
        echo "dhcp host ${self.input.mac} already present"
      else
        virsh -q -c '${self.input.uri}' net-update '${self.input.net}' add ip-dhcp-host \
          "<host mac='${self.input.mac}' name='${self.input.name}' ip='${self.input.ip}'/>" --live --config
      fi
    EOT
  }
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      virsh -q -c '${self.input.uri}' net-update '${self.input.net}' delete ip-dhcp-host \
        "<host mac='${self.input.mac}' name='${self.input.name}' ip='${self.input.ip}'/>" --live --config || true
    EOT
  }
}

resource "libvirt_volume" "disk" {
  name             = "${var.name}.qcow2"
  pool             = var.pool
  format           = "qcow2"
  base_volume_name = var.base_volume_name
  base_volume_pool = var.base_volume_pool
  size             = var.disk_gb * 1073741824
}

resource "libvirt_cloudinit_disk" "ci" {
  name = "${var.name}-cidata.iso"
  pool = var.pool
  user_data = templatefile("${path.module}/templates/user-data.${var.os_kind}.tftpl", {
    name      = var.name
    sudo_line = local.sudo_line
    pwhash    = var.sudo_password_hash
    pubkey    = var.ssh_pubkey
  })
  meta_data = "instance-id: ${var.name}\nlocal-hostname: ${var.name}\n"
  # The provider always writes a network-config file, even when empty. FreeBSD's
  # nuageinit fails to parse an empty one ("error parsing nocloud network-config")
  # and aborts before it writes the runcmd script (no sudoers, no sudo for ops).
  # Give it a valid minimal v2 config. Debian's cloud-init tolerates empty.
  network_config = local.freebsd ? "version: 2\nethernets:\n  vtnet0:\n    dhcp4: true\n" : null

  # Like the scripts: cloud-init input only matters at first boot. Rebuild a
  # guest with `-replace`, not by editing the live ISO under it.
  lifecycle {
    ignore_changes = [user_data, meta_data, network_config]
  }
}

resource "libvirt_domain" "this" {
  name      = var.name
  memory    = var.memory_mb
  vcpu      = var.vcpu
  autostart = true
  cloudinit = libvirt_cloudinit_disk.ci.id

  # FreeBSD's first boot (nuageinit) ends powered off; <on_poweroff>restart
  # brings it back up declaratively (up-bsd.sh polled and `virsh start`ed).
  # Provider 0.8 has no on_poweroff attribute, hence the XSLT. Side effect: a
  # deliberate guest poweroff also restarts it.
  # No graphics/video device (up.sh used --graphics none; the provider adds
  # spice + cirrus by default). The FreeBSD stylesheet also sets
  # <on_poweroff>restart (above).
  xml {
    xslt = file("${path.module}/templates/${var.os_kind}.xsl")
  }

  cpu {
    mode = "host-passthrough"
  }

  disk {
    volume_id = libvirt_volume.disk.id
  }

  network_interface {
    network_name = var.network
    mac          = var.mac
  }

  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }

  depends_on = [terraform_data.dhcp]
}
