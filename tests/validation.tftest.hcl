# Input validation tests: each rejected value must fail the plan on the right variable.

mock_provider "unifi" {}

variables {
  zone_ids    = { "LAB" = "zone-lab", "Internal" = "zone-internal" }
  network_ids = { lab = "net-lab" }
  groups = {
    dns = { members = ["192.0.2.53"] }
    web = { type = "port-group", members = ["80", "443"] }
  }
}

# ---------------------------------------------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------------------------------------------

run "unknown_group_type_refused" {
  command = plan
  variables {
    groups = { g = { type = "mac-group", members = ["aa:bb:cc:dd:ee:ff"] } }
  }
  expect_failures = [var.groups]
}

run "group_without_member_refused" {
  command = plan
  variables {
    groups = { g = { members = [] } }
  }
  expect_failures = [var.groups]
}

run "address_group_with_slash_32_refused" {
  command = plan
  variables {
    groups = { g = { members = ["192.0.2.53/32"] } }
  }
  expect_failures = [var.groups]
}

run "address_group_with_ipv6_member_refused" {
  command = plan
  variables {
    groups = { g = { members = ["2001:db8::1"] } }
  }
  expect_failures = [var.groups]
}

run "address_group_with_hostname_refused" {
  command = plan
  variables {
    groups = { g = { members = ["dns.example.test"] } }
  }
  expect_failures = [var.groups]
}

run "ipv6_group_with_ipv4_member_refused" {
  command = plan
  variables {
    groups = { g = { type = "ipv6-address-group", members = ["192.0.2.1"] } }
  }
  expect_failures = [var.groups]
}

run "port_group_with_text_member_refused" {
  command = plan
  variables {
    groups = { g = { type = "port-group", members = ["https"] } }
  }
  expect_failures = [var.groups]
}

run "port_group_with_port_above_65535_refused" {
  command = plan
  variables {
    groups = { g = { type = "port-group", members = ["70000"] } }
  }
  expect_failures = [var.groups]
}

# ---------------------------------------------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------------------------------------------

run "unknown_action_refused" {
  command = plan
  variables {
    policies = { p = { action = "PERMIT", source = { zone = "LAB" }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "unknown_protocol_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "gre", source = { zone = "LAB" }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "unknown_ip_version_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", ip_version = "IPV5", source = { zone = "LAB" }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "create_allow_respond_on_icmp_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "icmp", create_allow_respond = true, source = { zone = "LAB" }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "icmp_without_create_allow_respond_accepted" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "icmp", source = { zone = "LAB" }, destination = { zone = "Internal" } } }
  }
}

run "endpoint_matching_networks_and_ips_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB", networks = ["lab"], ips = ["192.0.2.1"] }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "endpoint_matching_group_and_regions_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB" }, destination = { zone = "Internal", ip_group = "dns", regions = ["FR"] } } }
  }
  expect_failures = [var.policies]
}

run "ports_and_port_group_together_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "80", port_group = "web" } } }
  }
  expect_failures = [var.policies]
}

run "ports_without_a_protocol_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "443" } } }
  }
  expect_failures = [var.policies]
}

run "ports_with_protocol_all_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "443" } } }
  }
  expect_failures = [var.policies]
}

run "ports_with_a_semicolon_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "80;443" } } }
  }
  expect_failures = [var.policies]
}

run "port_above_65535_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "70000" } } }
  }
  expect_failures = [var.policies]
}

run "ports_list_and_range_accepted" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp_udp", source = { zone = "LAB" }, destination = { zone = "Internal", ports = "53,80,8000-8100" } } }
  }
}

run "lowercase_region_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "External", regions = ["fr"] }, destination = { zone = "LAB" } } }
  }
  expect_failures = [var.policies]
}

run "unknown_network_key_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB", networks = ["missing"] }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

run "unknown_ip_group_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB" }, destination = { zone = "Internal", ip_group = "missing" } } }
  }
  expect_failures = [var.policies]
}

run "ip_group_that_is_a_port_group_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = "LAB" }, destination = { zone = "Internal", ip_group = "web" } } }
  }
  expect_failures = [var.policies]
}

run "unknown_port_group_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp", source = { zone = "LAB" }, destination = { zone = "Internal", port_group = "missing" } } }
  }
  expect_failures = [var.policies]
}

run "port_group_that_is_an_address_group_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "tcp", source = { zone = "LAB" }, destination = { zone = "Internal", port_group = "dns" } } }
  }
  expect_failures = [var.policies]
}

run "empty_zone_name_refused" {
  command = plan
  variables {
    policies = { p = { action = "ALLOW", protocol = "all", source = { zone = " " }, destination = { zone = "Internal" } } }
  }
  expect_failures = [var.policies]
}

# ---------------------------------------------------------------------------------------------------------------
# Port forwards
# ---------------------------------------------------------------------------------------------------------------

run "port_forward_with_unknown_protocol_refused" {
  command = plan
  variables {
    port_forwards = { f = { protocol = "icmp", wan_port = "443", forward_ip = "192.0.2.15" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_with_unknown_wan_interface_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_interface = "wan3", wan_port = "443", forward_ip = "192.0.2.15" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_with_text_port_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "https", forward_ip = "192.0.2.15" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_with_port_above_65535_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "443", forward_port = "99999", forward_ip = "192.0.2.15" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_to_an_address_with_a_prefix_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "443", forward_ip = "192.0.2.15/32" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_to_an_ipv6_address_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "443", forward_ip = "2001:db8::15" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_with_invalid_wan_address_refused" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "443", forward_ip = "192.0.2.15", wan_ip_address = "somewhere" } }
  }
  expect_failures = [var.port_forwards]
}

run "port_forward_with_wan_address_any_accepted" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "443", forward_ip = "192.0.2.15", wan_ip_address = "any" } }
  }
}

run "port_forward_with_port_range_accepted" {
  command = plan
  variables {
    port_forwards = { f = { wan_port = "8000-8100", forward_ip = "192.0.2.15" } }
  }
}
