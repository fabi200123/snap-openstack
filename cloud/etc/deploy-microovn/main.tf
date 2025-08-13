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

resource "juju_application" "microcluster-token-distributor" {
  name  = "microcluster-token-distributor"
  trust = true
  model = var.machine_model
  units = length(var.machine_ids)

  charm {
    name    = "microcluster-token-distributor"
    channel = var.charm_microovn_channel    # e.g. latest/edge
    base    = "ubuntu@24.04"
  }
}

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

  endpoint_bindings = var.endpoint_bindings   # include tls-certificates, ovsdb-cms → management
}

resource "juju_integration" "microovn-microcluster-token-distributor" {
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "cluster"
  }

  application {
    name     = juju_application.microcluster-token-distributor.name
    endpoint = "microcluster-cluster"
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

resource "juju_integration" "microovn-ovsdb-cms" {
  count = (var.ovn-relay-offer-url != null) ? 1 : 0
  model = var.machine_model

  application {
    name     = juju_application.microovn.name
    endpoint = "ovsdb-external"
  }

  application {
    offer_url = var.ovn-relay-offer-url
  }
}

output "microovn-application-name" {
  value = juju_application.microovn.name
}
