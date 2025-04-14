# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.5.7"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 3.0.0"
    }
  }
}

provider "openstack" {}

resource "openstack_images_image_v2" "caas-image" {
  name             = var.image-name
  image_source_url = var.image-source-url
  container_format = var.image-container-format
  disk_format      = var.image-disk-format
  decompress       = true
  visibility       = "public"
  properties       = var.image-properties
}
