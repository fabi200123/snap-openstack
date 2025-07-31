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
    count = (var.tls_certificates_provider_name != null) ? 1 : 0
    model = var.machine_model

    application {
      name     = juju_application.microovn.name
      endpoint = "tls-certificates"
    }

    application {
      name = var.tls_certificates_provider_name
      endpoint  = "certificates"
    }
}

resource "juju_integration" "microovn-ovsdb-relation" {
    model = var.machine_model
    
    application {
        name     = juju_application.microovn.name
        endpoint = "ovsdb"
    }
    
    application {
        name = var.ovsb_provider_name
        endpoint  = "ovsdb-cms"
    }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
