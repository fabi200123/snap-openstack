# microovn.tf
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
    name    = "microovn"
    channel = var.charm_microovn_channel    # e.g. latest/edge
    base    = "ubuntu@24.04"
  }

  # this is key; without it the charm won’t install the snap
  config = {
    snap-channel = var.microovn_snap_channel  # e.g. latest/edge
  }

  endpoint_bindings = var.endpoint_bindings   # include tls-certificates, ovsdb-cms → management
}

# OPTIONAL CMRs – only create if offers are provided (match your Python)
resource "juju_integration" "microovn-certs" {
  count = (var["ca-offer-url"] != null) ? 1 : 0
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "tls-certificates"
  }

  application {
    offer_url = var["ca-offer-url"]
  }
}

resource "juju_integration" "microovn-ovsdb-cms" {
  count = (var["ovn-relay-offer-url"] != null) ? 1 : 0
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "ovsdb-cms"
  }

  application {
    offer_url = var["ovn-relay-offer-url"]
  }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
