# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

variable "charm_microovn_channel" {
  description = "Operator channel for microovn deployment"
  type        = string
  default     = "latest/edge"
}

variable "charm_microovn_revision" {
  description = "Operator channel revision for microovn deployment"
  type        = number
  default     = null
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
  description = "Endpoint bindings for openstack-hypervisor"
  type        = set(map(string))
  default     = null
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
  default     = null
}

# Mandatory relation, no defaults
variable "ovn-relay-offer-url" {
  description = "Offer URL for ovn relay service"
  type        = string
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