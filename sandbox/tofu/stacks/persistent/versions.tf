terraform {
  required_version = ">= 1.7"
  required_providers {
    # Pinned to 0.8.x: 0.9 rewrote the schema (new resource/attribute model),
    # so a bare ">= 0.8" would break this code on the next init -upgrade.
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8.3"
    }
  }

  # State and plan are encrypted client-side. The passphrase comes from
  # TF_VAR_state_passphrase (tf.sh reads ~/sandbox/secrets/tofu-passphrase).
  encryption {
    key_provider "pbkdf2" "main" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "main" {
      keys = key_provider.pbkdf2.main
    }
    state {
      method   = method.aes_gcm.main
      enforced = true
    }
    plan {
      method   = method.aes_gcm.main
      enforced = true
    }
  }
}

provider "libvirt" {
  uri = var.libvirt_uri
}
