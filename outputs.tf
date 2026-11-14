output "group_ids" {
  description = "ID of each firewall group, by key."
  type        = map(string)
  value       = { for key, group in unifi_firewall_group.this : key => group.id }
}

output "policy_ids" {
  description = "ID of each firewall policy, by key."
  type        = map(string)
  value = merge(
    { for key, policy in unifi_firewall_policy.allow : key => policy.id },
    { for key, policy in unifi_firewall_policy.deny : key => policy.id },
  )
}

output "port_forward_ids" {
  description = "ID of each port forward, by key."
  type        = map(string)
  value       = { for key, forward in unifi_port_forward.this : key => forward.id }
}

output "zone_ids" {
  description = "ID of every zone named by a policy, by zone name: the ones given in zone_ids and the ones found in the controller."
  type        = map(string)
  value       = local.zone_id
}
