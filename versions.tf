terraform {
  # 1.15 adds explicit type constraints on outputs, used in outputs.tf.
  required_version = ">= 1.15"

  # A module declares a lower bound only: the live repository pins exact versions.
  # 0.62.0 is the oldest release checked: it has the nested attributes (0.60), and a port forward that is not re-enabled
  # or widened to UDP by a default (0.62). All 42 fields used by this module and by terraform-unifi-network exist in it.
  required_providers {
    unifi = {
      source  = "ubiquiti-community/unifi"
      version = ">= 0.62.0"
    }
  }
}
