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
  description = "Endpoint bindings for microovn"
  type        = set(map(string))
  default     = null
}

variable "snap_channel" {
  description = "Snap channel to deploy microovn snap from"
  type        = string
  default     = "latest/edge"
}

variable "ovn-relay-offer-url" {
  description = "Offer URL for OVN relay"
  type        = string
  default     = null
}

variable "ca-offer-url" {
  description = "Offer URL for certificate authority"
  type        = string
  default     = null
}
