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

  endpoint_bindings = var.endpoint_bindings
}

resource "juju_integration" "microovn-ovn" {
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "ovsdb-cms"
  }

  application {
    offer_url = var.ovn-relay-offer-url
  }
}

resource "juju_integration" "microovn-certs" {
  count = (var.ca-offer-url != null) ? 1 : 0
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "certificates"
  }

  application {
    offer_url = var.ca-offer-url
  }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
