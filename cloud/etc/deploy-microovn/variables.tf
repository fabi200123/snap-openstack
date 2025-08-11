# variables.tf additions (or ensure they exist)
variable "charm_microovn_channel" {
  type    = string
  default = "latest/edge"
}

variable "microovn_snap_channel" {
  description = "MicroOVN snap channel to install via the charm"
  type        = string
  default     = "latest/edge"
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

variable "ca-offer-url" {
  type    = string
  default = null
}

variable "ovn-relay-offer-url" {
  type    = string
  default = null
}

variable "machine_model" { type = string }
variable "machine_ids"   { type = list(string) default = [] }
