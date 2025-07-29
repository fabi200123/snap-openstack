# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

terraform {

  required_providers {
    juju = {
      source  = "juju/juju"
      version = "= 0.20.0"
    }
  }

}

provider "juju" {}

data "juju_model" "machine_model" {
  name = var.machine_model
}

resource "juju_application" "microovn" {
  name  = "microovn"
  trust = true
  model = data.juju_model.machine_model.name
  units = length(var.machine_ids)

  charm {
    name     = "microovn"
    channel  = var.charm_microovn_channel
    revision = var.charm_microovn_revision
    base     = "ubuntu@24.04"
  }

  config = merge({
    snap-channel = var.microovn_channel
  }, var.charm_microovn_config)
}

output "ceph-application-name" {
  value = juju_application.microovn.name
}
