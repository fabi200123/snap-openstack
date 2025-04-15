# Terraform manifest for deployment of COS Lite
#
# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

output "prometheus-metrics-offer-url" {
  description = "URL of the prometheus metrics endpoint offer"
  value       = juju_offer.prometheus-metrics-offer.url
}

output "prometheus-receive-remote-write-offer-url" {
  description = "URL of the prometheus receive remote write endpoint offer"
  value       = juju_offer.prometheus-receive-remote-write-offer.url
}

output "loki-logging-offer-url" {
  description = "URL of the loki logging offer"
  value       = juju_offer.loki-logging-offer.url
}

output "grafana-dashboard-offer-url" {
  description = "URL of the grafana dashboard offer"
  value       = juju_offer.grafana-dashboard-offer.url
}

output "alertmanager-karma-dashboard-offer-url" {
  description = "URL of the alertmanager karma dashboard endpoint offer"
  value       = juju_offer.alertmanager-karma-dashboard-offer.url
}
