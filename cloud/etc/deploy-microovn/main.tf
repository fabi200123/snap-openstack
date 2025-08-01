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
}

resource "juju_integration" "microovn-certificate-relation" {
    count = (var.tls-certificates-offer-url != null) ? 1 : 0
    model = var.machine_model

    application {
      name     = juju_application.microovn.name
      endpoint = "tls-certificates"
    }

    application {
      offer_url = var.tls-certificates-offer-url
    }
}

resource "juju_integration" "microovn-ovsdb-relation" {
    count = (var.ovn-ovsdb-offer-url != null) ? 1 : 0
    model = var.machine_model
    
    application {
        name     = juju_application.microovn.name
        endpoint = "ovsdb"
    }
    
    application {
        offer_url = var.ovn-ovsdb-offer-url
    }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
