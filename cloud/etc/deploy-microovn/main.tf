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
  name        = "microovn"
  trust       = true
  model       = var.machine_model
  units       = length(var.machine_ids)

  charm {
    name     = "microovn"
    channel  = var.charm_microovn_channel
    base     = "ubuntu@24.04"
  }

  # IMPORTANT: ensure the charm knows which snap channel to install
  config = {
    snap-channel = var.microovn_snap_channel
  }

  # Bind endpoints to the management space to avoid relation/space mismatch waits
  endpoint_bindings = var.endpoint_bindings
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
