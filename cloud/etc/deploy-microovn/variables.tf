# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

variable "charm_microovn_channel" {
  type    = string
  default = "latest/edge"
}

variable "microovn_snap_channel" {
  description = "MicroOVN snap channel to install via the charm"
  type        = string
  default     = "latest/edge"
}

variable "charm_microovn_config" {
  description = "Operator config for microovn deployment"
  type        = map(string)
  default     = {}
}

variable "microovn_channel" {
  description = "K8S channel to deploy, not the operator channel"
  default     = "latest/edge"
}

variable "machine_ids" {
  description = "List of machine ids to include"
  type        = list(string)
  default     = []
}

variable "machine_model" {
  description = "Model to deploy to"
  type        = string
}

variable "endpoint_bindings" {
  description = "Endpoint bindings for microovn (spaces)"
  type = list(object({
    endpoint = optional(string)
    space    = string
  }))
  default = [
    { space = "management" },
    { endpoint = "tls-certificates", space = "management" },
    { endpoint = "ovsdb-cms",        space = "management" },
  ]
}

# Mandatory relation, no defaults
variable "rabbitmq-offer-url" {
  description = "Offer URL for openstack rabbitmq"
  type        = string
}

# Mandatory relation, no defaults
variable "keystone-offer-url" {
  description = "Offer URL for openstack keystone identity-credentials relation"
  type        = string
}

variable "cert-distributor-offer-url" {
  description = "Offer URL for openstack keystone certificate-transfer relation"
  type        = string
  default     = null
}

variable "ca_offer_url" {
  description = "Offer URL for Certificates"
  type        = string
  default     = "sunbeam/openstack.certificate-authority"
}

# Mandatory relation, no defaults
variable "ovn-relay-offer-url" {
  description = "Offer URL for ovn relay service"
  type        = string
  default     = "sunbeam/openstack.ovn-relay"
}

variable "ceilometer-offer-url" {
  description = "Offer URL for openstack ceilometer"
  type        = string
  default     = null
}

variable "cinder-volume-ceph-application-name" {
  description = "Name for cinder-volume-ceph application"
  type        = string
  default     = null
}

# Mandatory relation, no defaults
variable "nova-offer-url" {
  description = "Offer URL for openstack nova"
  type        = string
}

variable "masakari-offer-url" {
  description = "Offer URL for openstack masakari"
  type        = string
  default     = null
}