# Firewall groups, zone-based firewall policies and port forwards of a UniFi gateway.
# Policies name zones, networks and groups instead of IDs: the module resolves the IDs.
#
# The controller appends a policy at the end of its pair of zones and cannot reorder it. Policies that block are therefore created
# after the policies that allow (depends_on below), so an allow list followed by a block works the first time. Adding an allow policy later,
# to a pair of zones that already has a block policy, places it after the block: replace the block policy, or reorder them in the UniFi UI.

locals {
  # Every zone named by a policy. The ones this configuration creates come with their ID (zone_ids); the others are looked up by name.
  zone_names            = toset(flatten([for policy in values(var.policies) : [policy.source.zone, policy.destination.zone]]))
  zone_names_to_look_up = toset([for zone in local.zone_names : zone if !contains(keys(var.zone_ids), zone)])

  zone_id = {
    for zone in local.zone_names :
    zone => contains(keys(var.zone_ids), zone) ? var.zone_ids[zone] : data.unifi_firewall_zone.lookup[zone].id
  }

  # Source and destination of every policy, in the shape of the provider. What a policy does not match stays null.
  endpoints = {
    for key, policy in var.policies : key => {
      for side, endpoint in { source = policy.source, destination = policy.destination } : side => {
        zone_id                      = local.zone_id[endpoint.zone]

        matching_target = (
          length(endpoint.networks) > 0 ? "NETWORK" :
          endpoint.ip_group != null || length(endpoint.ips) > 0 ? "IP" :
          length(endpoint.regions) > 0 ? "REGION" : "ANY"
        )

        network_ids = length(endpoint.networks) > 0 ? [for network in endpoint.networks : var.network_ids[network]] : null
        ip_group_id = endpoint.ip_group != null ? unifi_firewall_group.this[endpoint.ip_group].id : null
        ips         = length(endpoint.ips) > 0 ? endpoint.ips : null
        regions     = length(endpoint.regions) > 0 ? endpoint.regions : null

        port_matching_type = endpoint.ports != null ? "SPECIFIC" : (endpoint.port_group != null ? "OBJECT" : "ANY")
        port               = endpoint.ports
        port_group_id      = endpoint.port_group != null ? unifi_firewall_group.this[endpoint.port_group].id : null
      }
    }
  }

  # An ALLOW policy also allows the return traffic, unless it is icmp, which the controller refuses.
  create_allow_respond = {
    for key, policy in var.policies : key => (
      policy.create_allow_respond != null ? policy.create_allow_respond :
      policy.action == "ALLOW" && !contains(["icmp", "icmpv6"], coalesce(policy.protocol, "all")) ? true : null
    )
  }

  allow_policies = { for key, policy in var.policies : key => policy if policy.action == "ALLOW" }
  deny_policies  = { for key, policy in var.policies : key => policy if policy.action != "ALLOW" }
}

data "unifi_firewall_zone" "lookup" {
  for_each = local.zone_names_to_look_up

  name = each.value
}

resource "unifi_firewall_group" "this" {
  for_each = var.groups

  name    = each.value.name != null ? each.value.name : "${var.name_prefix}${each.key}"
  type    = each.value.type
  members = toset(each.value.members)
}

resource "unifi_firewall_policy" "allow" {
  for_each = local.allow_policies

  name                 = each.value.name != null ? each.value.name : "${var.name_prefix}${each.key}"
  description          = each.value.description
  action               = each.value.action
  protocol             = each.value.protocol
  ip_version           = each.value.ip_version
  create_allow_respond = local.create_allow_respond[each.key]
  logging              = each.value.logging
  enabled              = each.value.enabled
  source               = local.endpoints[each.key].source
  destination          = local.endpoints[each.key].destination
}

resource "unifi_firewall_policy" "deny" {
  for_each = local.deny_policies

  name                 = each.value.name != null ? each.value.name : "${var.name_prefix}${each.key}"
  description          = each.value.description
  action               = each.value.action
  protocol             = each.value.protocol
  ip_version           = each.value.ip_version
  create_allow_respond = local.create_allow_respond[each.key]
  logging              = each.value.logging
  enabled              = each.value.enabled
  source               = local.endpoints[each.key].source
  destination          = local.endpoints[each.key].destination

  # Created after every allow policy, because the controller evaluates policies in creation order within a pair of zones.
  depends_on = [unifi_firewall_policy.allow]
}

resource "unifi_port_forward" "this" {
  for_each = var.port_forwards

  name     = each.value.name != null ? each.value.name : "${var.name_prefix}${each.key}"
  enabled  = each.value.enabled
  protocol = each.value.protocol
  logging  = each.value.logging

  wan = {
    interface  = each.value.wan_interface
    ip_address = each.value.wan_ip_address
    port       = each.value.wan_port
  }

  forward = {
    ip   = each.value.forward_ip
    port = each.value.forward_port != null ? each.value.forward_port : each.value.wan_port
  }

  destination_ips = length(each.value.destination_ips) > 0 ? each.value.destination_ips : null
}
