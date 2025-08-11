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

resource "juju_application" "microovn" {
  name  = "microovn"
  trust = true
  model = var.machine_model
  units = length(var.machine_ids)

  charm {
    name     = "microovn"
    channel  = var.charm_microovn_channel
    revision = var.charm_microovn_revision
    base     = "ubuntu@24.04"
  }

}

resource "juju_integration" "microovn-certificates" {
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "tls-certificates"
  }

  application {
    offer_url = "sunbeam/openstack.certificate-authority"
  }
}

resource "juju_integration" "hypervisor-ovn" {
  model = var.machine_model

  application {
    name     = juju_application.openstack-hypervisor.name
    endpoint = "ovsdb-cms"
  }

  application {
    offer_url = "sunbeam/openstack.ovn-relay"
  }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
