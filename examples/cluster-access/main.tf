# The firewall of a Kubernetes cluster that lives in its own zone and network: what the cluster may reach, and who may reach it.
# In a real project, pin the module source to a tag:
#   source = "git::https://github.com/itlinuxfr/terraform-unifi-firewall.git?ref=v1.0.0"
# The relative source is used by CI: it tests the code of the current branch.
#
# The zone and the network come from terraform-unifi-network (its zone_id and network_id outputs). Policies name them by key, not by ID.
# Internal is looked up by name in the controller.

terraform {
  required_version = ">= 1.15"
}

variable "cluster_zone_id" {
  description = "ID of the cluster firewall zone (zone_id output of terraform-unifi-network)."
  type        = string
}

variable "cluster_network_id" {
  description = "ID of the cluster network (network_id output of terraform-unifi-network)."
  type        = string
}

module "firewall" {
  source = "../../"

  name_prefix = "k8s-prod-"

  zone_ids    = { "K8S-PROD" = var.cluster_zone_id }
  network_ids = { cluster = var.cluster_network_id }

  groups = {
    # CIDR blocks that cover .2-.9 (virtual IP, nodes) and .10-.19 (load balancer) of 192.0.2.0/27.
    nodes   = { members = ["192.0.2.2/31", "192.0.2.4/30", "192.0.2.8/31"] }
    metallb = { members = ["192.0.2.10/31", "192.0.2.12/30", "192.0.2.16/30"] }
    admins  = { members = ["198.51.100.10", "198.51.100.11"] }
    freeipa = { members = ["198.51.100.53"] }
    proxmox = { members = ["198.51.100.20"] }
  }

  policies = {
    to_freeipa_dns = {
      description = "DNS lookups and RFC2136 updates to FreeIPA (cert-manager, ExternalDNS)."
      action      = "ALLOW"
      protocol    = "tcp_udp"
      source      = { zone = "K8S-PROD", networks = ["cluster"] }
      destination = { zone = "Internal", ip_group = "freeipa", ports = "53" }
    }

    to_freeipa_acme = {
      description = "Certificates from the ACME server of FreeIPA (cert-manager)."
      action      = "ALLOW"
      protocol    = "tcp"
      source      = { zone = "K8S-PROD", networks = ["cluster"] }
      destination = { zone = "Internal", ip_group = "freeipa", ports = "443" }
    }

    to_proxmox_api = {
      description = "Disk provisioning by the Proxmox CSI plugin."
      action      = "ALLOW"
      protocol    = "tcp"
      source      = { zone = "K8S-PROD", networks = ["cluster"] }
      destination = { zone = "Internal", ip_group = "proxmox", ports = "8006" }
    }

    admins_to_apis = {
      description = "kubectl (6443) and talosctl (50000) from the admin workstations."
      action      = "ALLOW"
      protocol    = "tcp"
      source      = { zone = "Internal", ip_group = "admins" }
      destination = { zone = "K8S-PROD", ip_group = "nodes", ports = "6443,50000" }
    }

    admins_to_load_balancer = {
      description = "HTTP and HTTPS to the services published by the load balancer."
      action      = "ALLOW"
      protocol    = "tcp"
      source      = { zone = "Internal", ip_group = "admins" }
      destination = { zone = "K8S-PROD", ip_group = "metallb", ports = "80,443" }
    }
  }
}

output "policy_ids" {
  value = module.firewall.policy_ids
}
