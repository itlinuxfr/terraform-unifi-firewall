# Publish one HTTPS service on the Internet, and let in only a few countries.
#
# The port forward sends WAN port 443 to the service. The UniFi gateway then creates its own zone policy for it. The two policies below
# are evaluated before that one: the first lets the allowed countries in, the second blocks every other source to the same address and port.
# The block policy is created after the allow policy (the module orders them), so the allow comes first.
# Country matching is approximate (VPNs, mobile operators abroad, badly located addresses).

terraform {
  required_version = ">= 1.15"
}

variable "service_zone_id" {
  description = "ID of the firewall zone of the service (zone_id output of terraform-unifi-network)."
  type        = string
}

module "firewall" {
  source = "../../"

  zone_ids = { "SERVICES" = var.service_zone_id }

  port_forwards = {
    public_web = {
      name       = "HTTPS to the public web service"
      wan_port   = "443"
      forward_ip = "192.0.2.15"
    }
  }

  policies = {
    public_web_allowed_countries = {
      description = "Internet to the public web service, from the allowed countries only."
      action      = "ALLOW"
      protocol    = "tcp"
      source      = { zone = "External", regions = ["FR"] }
      destination = { zone = "SERVICES", ips = ["192.0.2.15"], ports = "443" }
    }

    public_web_other_countries = {
      description = "Internet to the public web service: everything the policy before did not allow."
      action      = "BLOCK"
      protocol    = "tcp"
      source      = { zone = "External" }
      destination = { zone = "SERVICES", ips = ["192.0.2.15"], ports = "443" }
    }
  }
}
