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

variable "tls-certificates-offer-url" {
  description = "Name of the TLS certificates provider application"
  type        = string
}

variable "ovn-ovsdb-offer-url" {
  description = "Name of the OVSB provider application"
  type        = string
}