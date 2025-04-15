# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

variable "ubuntu-advantage-channel" {
  description = "Channel to use for deployment of ubuntu-advantage charm"
  type        = string
  default     = "latest/edge"
}

variable "machine-model" {
  description = "Name of model to deploy ubuntu-pro into."
  type        = string
}

variable "token" {
  description = "Ubuntu Pro token to use to attach support subscriptions"
  type        = string
  default     = ""
}
