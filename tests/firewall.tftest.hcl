# Tests without a controller: the UniFi provider is replaced by a mock provider.
# `command = plan` creates nothing. IDs that the controller computes (groups, policies) are unknown at plan time and are not checked.

mock_provider "unifi" {}

variables {
  name_prefix = "lab-"
  zone_ids    = { "LAB" = "zone-lab" }
  network_ids = { lab = "net-lab" }
  groups = {
    dns   = { members = ["192.0.2.53"] }
    nodes = { members = ["192.0.2.2/31", "192.0.2.4/30"] }
    web   = { type = "port-group", members = ["80", "443", "8000-8100"] }
  }
}

run "nothing_configured_creates_nothing" {
  command = plan

  variables {
    groups = {}
  }

  assert {
    condition = (
      length(unifi_firewall_group.this) == 0 &&
      length(unifi_firewall_policy.allow) == 0 &&
      length(unifi_firewall_policy.deny) == 0 &&
      length(unifi_port_forward.this) == 0 &&
      length(data.unifi_firewall_zone.lookup) == 0
    )
    error_message = "An empty configuration must create and look up nothing."
  }
}

run "groups_get_the_prefix_the_type_and_the_members" {
  command = plan

  variables {
    groups = {
      dns   = { members = ["192.0.2.53"] }
      nodes = { members = ["192.0.2.2/31", "192.0.2.4/30"], name = "custom-nodes" }
      web   = { type = "port-group", members = ["80", "443", "8000-8100"] }
      v6    = { type = "ipv6-address-group", members = ["2001:db8::/64", "2001:db8:1::5"] }
    }
  }

  assert {
    condition = (
      unifi_firewall_group.this["dns"].name == "lab-dns" &&
      unifi_firewall_group.this["nodes"].name == "custom-nodes" &&
      unifi_firewall_group.this["dns"].type == "address-group" &&
      unifi_firewall_group.this["web"].type == "port-group" &&
      unifi_firewall_group.this["v6"].type == "ipv6-address-group"
    )
    error_message = "Groups must be named with the prefix unless a name is given, and keep their type (address-group by default)."
  }

  assert {
    condition     = unifi_firewall_group.this["nodes"].members == toset(["192.0.2.2/31", "192.0.2.4/30"]) && unifi_firewall_group.this["web"].members == toset(["80", "443", "8000-8100"])
    error_message = "Group members must reach the controller."
  }
}

run "allow_policy_resolves_zones_networks_groups_and_ports" {
  command = plan

  variables {
    policies = {
      to_dns = {
        description = "DNS to FreeIPA"
        action      = "ALLOW"
        protocol    = "tcp_udp"
        source      = { zone = "LAB", networks = ["lab"] }
        destination = { zone = "Internal", ip_group = "dns", ports = "53" }
      }
    }
  }

  assert {
    condition = (
      unifi_firewall_policy.allow["to_dns"].name == "lab-to_dns" &&
      unifi_firewall_policy.allow["to_dns"].action == "ALLOW" &&
      unifi_firewall_policy.allow["to_dns"].protocol == "tcp_udp" &&
      unifi_firewall_policy.allow["to_dns"].description == "DNS to FreeIPA"
    )
    error_message = "The policy name must be the prefix and the key, and the action, protocol and description must reach the controller."
  }

  assert {
    condition = (
      unifi_firewall_policy.allow["to_dns"].source.zone_id == "zone-lab" &&
      unifi_firewall_policy.allow["to_dns"].source.matching_target == "NETWORK" &&
      unifi_firewall_policy.allow["to_dns"].source.network_ids == tolist(["net-lab"])
    )
    error_message = "A zone given in zone_ids and a network key must be resolved to their IDs and matched as a network."
  }

  assert {
    condition = (
      unifi_firewall_policy.allow["to_dns"].destination.zone_id == data.unifi_firewall_zone.lookup["Internal"].id &&
      unifi_firewall_policy.allow["to_dns"].destination.matching_target == "IP" &&
      unifi_firewall_policy.allow["to_dns"].destination.port_matching_type == "SPECIFIC" &&
      unifi_firewall_policy.allow["to_dns"].destination.port == "53"
    )
    error_message = "A zone that is not in zone_ids must be looked up by name, a group must be matched as an IP match, and ports as a specific port match."
  }

  assert {
    condition     = unifi_firewall_policy.allow["to_dns"].create_allow_respond == true
    error_message = "An ALLOW policy must also allow the return traffic by default."
  }
}

run "port_group_is_matched_as_an_object" {
  command = plan

  variables {
    policies = {
      web = {
        action      = "ALLOW"
        protocol    = "tcp"
        source      = { zone = "LAB" }
        destination = { zone = "LAB", ip_group = "nodes", port_group = "web" }
      }
    }
  }

  assert {
    condition     = unifi_firewall_policy.allow["web"].destination.port_matching_type == "OBJECT" && unifi_firewall_policy.allow["web"].source.matching_target == "ANY" && unifi_firewall_policy.allow["web"].source.port_matching_type == "ANY"
    error_message = "A port group must be matched as an OBJECT, and an empty endpoint must match the whole zone."
  }
}

run "explicit_create_allow_respond_wins" {
  command = plan

  variables {
    policies = {
      one_way = {
        action               = "ALLOW"
        protocol             = "tcp"
        create_allow_respond = false
        source               = { zone = "LAB" }
        destination          = { zone = "LAB", ips = ["192.0.2.9"] }
      }
    }
  }

  assert {
    condition     = unifi_firewall_policy.allow["one_way"].create_allow_respond == false
    error_message = "A create_allow_respond that is set must win over the default."
  }
}

run "blocking_policies_are_a_separate_resource_created_after_the_allowing_ones" {
  command = plan

  variables {
    policies = {
      allow_web = {
        action      = "ALLOW"
        protocol    = "tcp"
        source      = { zone = "Internal" }
        destination = { zone = "LAB", ips = ["192.0.2.15"], ports = "443" }
      }
      block_rest = {
        action      = "BLOCK"
        protocol    = "tcp"
        source      = { zone = "Internal" }
        destination = { zone = "LAB", ips = ["192.0.2.15"], ports = "443" }
      }
      reject_ping = {
        action      = "REJECT"
        protocol    = "icmp"
        source      = { zone = "Internal" }
        destination = { zone = "LAB" }
      }
    }
  }

  assert {
    condition     = length(unifi_firewall_policy.allow) == 1 && length(unifi_firewall_policy.deny) == 2
    error_message = "ALLOW policies must go to the allow resource, BLOCK and REJECT to the deny resource."
  }

  assert {
    condition     = unifi_firewall_policy.deny["block_rest"].action == "BLOCK" && unifi_firewall_policy.deny["reject_ping"].action == "REJECT"
    error_message = "The deny resource must keep the BLOCK and REJECT actions."
  }
}

run "region_policy_on_the_external_zone" {
  command = plan

  variables {
    policies = {
      geo_allow = {
        action      = "ALLOW"
        protocol    = "tcp"
        source      = { zone = "External", regions = ["FR", "BE"] }
        destination = { zone = "LAB", ips = ["192.0.2.15"], ports = "443" }
      }
    }
  }

  assert {
    condition = (
      unifi_firewall_policy.allow["geo_allow"].source.matching_target == "REGION" &&
      unifi_firewall_policy.allow["geo_allow"].source.regions == tolist(["FR", "BE"]) &&
      unifi_firewall_policy.allow["geo_allow"].destination.matching_target == "IP" &&
      unifi_firewall_policy.allow["geo_allow"].destination.ips == tolist(["192.0.2.15"])
    )
    error_message = "Country codes must be matched as a REGION and an address as an IP match."
  }
}

run "zones_are_looked_up_only_when_not_given" {
  command = plan

  variables {
    policies = {
      a = { action = "ALLOW", protocol = "all", source = { zone = "LAB" }, destination = { zone = "Internal" } }
      b = { action = "ALLOW", protocol = "all", source = { zone = "External" }, destination = { zone = "LAB" } }
    }
  }

  assert {
    condition     = length(data.unifi_firewall_zone.lookup) == 2 && contains(keys(data.unifi_firewall_zone.lookup), "Internal") && contains(keys(data.unifi_firewall_zone.lookup), "External")
    error_message = "Only the zones that are not in zone_ids must be looked up."
  }

  assert {
    condition     = output.zone_ids["LAB"] == "zone-lab" && length(output.zone_ids) == 3
    error_message = "The zone_ids output must list every zone named by a policy, with the given IDs."
  }
}

run "port_forward_defaults" {
  command = plan

  variables {
    port_forwards = {
      web = { wan_port = "443", forward_ip = "192.0.2.15" }
    }
  }

  assert {
    condition = (
      unifi_port_forward.this["web"].name == "lab-web" &&
      unifi_port_forward.this["web"].enabled == true &&
      unifi_port_forward.this["web"].protocol == "tcp" &&
      unifi_port_forward.this["web"].wan.interface == "both" &&
      unifi_port_forward.this["web"].wan.port == "443" &&
      unifi_port_forward.this["web"].forward.ip == "192.0.2.15" &&
      unifi_port_forward.this["web"].forward.port == "443"
    )
    error_message = "A port forward must default to enabled, tcp, both WANs, and the WAN port as forward port."
  }
}

run "port_forward_with_every_option" {
  command = plan

  variables {
    port_forwards = {
      ssh = {
        name           = "SSH to the bastion"
        enabled        = false
        protocol       = "tcp_udp"
        wan_port       = "2222"
        wan_interface  = "wan2"
        wan_ip_address = "198.51.100.10"
        forward_ip     = "192.0.2.20"
        forward_port   = "22"
        logging        = true
        destination_ips = [
          { destination_ip = "any", interface = "wan" },
          { destination_ip = "any", interface = "wan2" },
        ]
      }
    }
  }

  assert {
    condition = (
      unifi_port_forward.this["ssh"].name == "SSH to the bastion" &&
      unifi_port_forward.this["ssh"].enabled == false &&
      unifi_port_forward.this["ssh"].protocol == "tcp_udp" &&
      unifi_port_forward.this["ssh"].logging == true &&
      unifi_port_forward.this["ssh"].wan.interface == "wan2" &&
      unifi_port_forward.this["ssh"].wan.ip_address == "198.51.100.10" &&
      unifi_port_forward.this["ssh"].forward.port == "22"
    )
    error_message = "Every port forward option must reach the controller."
  }

  assert {
    condition     = length(unifi_port_forward.this["ssh"].destination_ips) == 2 && unifi_port_forward.this["ssh"].destination_ips[1].interface == "wan2"
    error_message = "destination_ips must reach the controller."
  }
}

run "policy_name_override" {
  command = plan

  variables {
    policies = {
      custom = {
        name        = "Admins to the API"
        action      = "ALLOW"
        protocol    = "tcp"
        source      = { zone = "Internal" }
        destination = { zone = "LAB", ports = "6443,50000" }
      }
    }
  }

  assert {
    condition     = unifi_firewall_policy.allow["custom"].name == "Admins to the API" && unifi_firewall_policy.allow["custom"].destination.port == "6443,50000"
    error_message = "A policy name that is set must win over the prefix and the key, and a list of ports must be kept."
  }
}
