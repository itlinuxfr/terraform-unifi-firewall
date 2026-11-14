# terraform-unifi-firewall

Creates the firewall of a UniFi gateway with zone-based firewall (UniFi Network 9 or later): address and port groups, zone-to-zone policies,
and port forwards. It works with the [`ubiquiti-community/unifi`](https://registry.terraform.io/providers/ubiquiti-community/unifi) provider.
Policies name zones, networks and groups by name or by key, and the module resolves the IDs.

## Usage

```hcl
module "firewall" {
  source = "git::https://github.com/itlinuxfr/terraform-unifi-firewall.git?ref=v1.0.0"

  name_prefix = "k8s-prod-"
  zone_ids    = { "K8S-PROD" = module.network.zone_id }
  network_ids = { cluster = module.network.network_id }

  groups = {
    freeipa = { members = ["198.51.100.53"] }
  }

  policies = {
    to_freeipa_dns = {
      action      = "ALLOW"
      protocol    = "tcp_udp"
      source      = { zone = "K8S-PROD", networks = ["cluster"] }
      destination = { zone = "Internal", ip_group = "freeipa", ports = "53" }
    }
  }
}
```

See [`examples/`](examples/): the firewall of a Kubernetes cluster, and a port forward restricted to some countries. The zone and the network come from `terraform-unifi-network`.

## What to know
- **Policy order is not manageable.** The controller adds a policy at the end of its pair of zones, and its API has no way to reorder (the provider makes `index` read-only).
  Policies that block (`BLOCK`, `REJECT`) are created after the ones that allow, so an allow list followed by a block works the first time. If you add an allow policy later to a pair of zones that
  already has a block policy, the new one lands after the block and never matches: replace the block policy (`terraform apply -replace=...`) or reorder in the UniFi UI.
- **Zones are named, not given by ID.** A zone that is not in `zone_ids` is looked up by name in the controller (for example `Internal` and `External`). A zone that you create in the same run is not there
  yet at plan time, so pass it in `zone_ids`, for example from the `zone_id` output of `terraform-unifi-network`.
- **ALLOW policies also allow the return traffic** (`create_allow_respond`), except `icmp` and `icmpv6`, which the controller refuses. Set it yourself to override.
- **Country matching** (`regions`) is only accepted by the controller on an external zone, needs at least one code, and is approximate (VPNs, operators abroad, badly located addresses).
- **A single address is written without `/32`** in an address group: the controller refuses that notation. Group members are IP addresses or CIDR blocks, not ranges.
- **A port forward needs `enabled`**, which the provider deprecates but still requires: a rule created without it is created disabled. The module always sets it, so Terraform prints a
  deprecation warning. The UniFi gateway also creates the zone policy that lets the traffic in, evaluated after the policies of this module.
- Unset values stay as the controller has them (`enabled`, `logging`, `ip_version`), so adopting existing policies does not change them.

## Moving existing resources to this module
Resource types stay the same, only their addresses change, so `moved` blocks in your root module move them without recreating them, for example from
`unifi_firewall_policy.to_freeipa_dns` to `module.firewall.unifi_firewall_policy.allow["to_freeipa_dns"]` (`deny` for a `BLOCK` or `REJECT` policy).
Run `terraform plan` first and check that it shows moves, not replacements. Not tested against a real controller.

## Contributing
Read [`AGENTS.md`](AGENTS.md) for conventions and commands, and [`SECURITY.md`](SECURITY.md) for security rules.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.15 |
| <a name="requirement_unifi"></a> [unifi](#requirement\_unifi) | >= 0.62.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_unifi"></a> [unifi](#provider\_unifi) | >= 0.62.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [unifi_firewall_group.this](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs/resources/firewall_group) | resource |
| [unifi_firewall_policy.allow](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs/resources/firewall_policy) | resource |
| [unifi_firewall_policy.deny](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs/resources/firewall_policy) | resource |
| [unifi_port_forward.this](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs/resources/port_forward) | resource |
| [unifi_firewall_zone.lookup](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs/data-sources/firewall_zone) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_groups"></a> [groups](#input\_groups) | Firewall groups, by key. A policy refers to a group by its key.<br/>- type: address-group (IPv4), ipv6-address-group or port-group.<br/>- members: IP addresses or CIDRs for an address group (a single address is written without /32: the controller refuses it), ports or ranges such as 8000-8100 for a port group.<br/>- name: name in the controller. Defaults to name\_prefix followed by the key. | <pre>map(object({<br/>    type    = optional(string, "address-group")<br/>    members = list(string)<br/>    name    = optional(string)<br/>  }))</pre> | `{}` | no |
| <a name="input_name_prefix"></a> [name\_prefix](#input\_name\_prefix) | Prefix added to the name of every group, and to the name of every policy and port forward that has no name of its own. For example k8s-prod- gives k8s-prod-nodes. | `string` | `""` | no |
| <a name="input_network_ids"></a> [network\_ids](#input\_network\_ids) | IDs of networks that policies can match, by key (for example the network\_id output of terraform-unifi-network). A policy names the key, not the ID. | `map(string)` | `{}` | no |
| <a name="input_policies"></a> [policies](#input\_policies) | Zone-based firewall policies, by key.<br/>- action: ALLOW, BLOCK or REJECT.<br/>- protocol: all, tcp, udp, tcp\_udp, icmp or icmpv6. Required when ports or port\_group are used.<br/>- create\_allow\_respond: also allow the return traffic. Null means true for an ALLOW policy (except icmp, which the controller refuses), and the controller value otherwise.<br/>- source and destination: zone is a zone name. Match at most one of networks (keys of network\_ids), ip\_group (key of groups), ips or regions<br/>  (two-letter country codes: the controller only accepts them on an external zone). Match ports with ports ("53", "80,443", "8000-8100") or with port\_group (key of groups).<br/>  With nothing set, the whole zone matches.<br/>- enabled, logging, ip\_version, description, name: null keeps the controller value or the default (name is name\_prefix followed by the key).<br/>The controller adds a policy at the end of its pair of zones and offers no way to reorder it: see the README. | <pre>map(object({<br/>    name                 = optional(string)<br/>    description          = optional(string)<br/>    action               = string<br/>    protocol             = optional(string)<br/>    ip_version           = optional(string)<br/>    create_allow_respond = optional(bool)<br/>    logging              = optional(bool)<br/>    enabled              = optional(bool)<br/>    source = object({<br/>      zone       = string<br/>      networks   = optional(list(string), [])<br/>      ip_group   = optional(string)<br/>      ips        = optional(list(string), [])<br/>      regions    = optional(list(string), [])<br/>      ports      = optional(string)<br/>      port_group = optional(string)<br/>    })<br/>    destination = object({<br/>      zone       = string<br/>      networks   = optional(list(string), [])<br/>      ip_group   = optional(string)<br/>      ips        = optional(list(string), [])<br/>      regions    = optional(list(string), [])<br/>      ports      = optional(string)<br/>      port_group = optional(string)<br/>    })<br/>  }))</pre> | `{}` | no |
| <a name="input_port_forwards"></a> [port\_forwards](#input\_port\_forwards) | Port forwards from the WAN to an address of the LAN, by key.<br/>- protocol: tcp, udp or tcp\_udp.<br/>- wan\_port, forward\_port: a port or a range. forward\_port defaults to wan\_port.<br/>- wan\_interface: wan, wan2 or both.<br/>- wan\_ip\_address: WAN address to match. Null matches any.<br/>- destination\_ips: extra destination address and interface pairs, for several WANs.<br/>- enabled: the provider deprecates this argument but still needs it: a rule created without it is created disabled, which never opens a port by mistake.<br/>  The module sets it, so Terraform prints a deprecation warning.<br/>The UniFi gateway also creates the zone policy that lets the traffic in: the policies of this module are evaluated before it. | <pre>map(object({<br/>    name           = optional(string)<br/>    enabled        = optional(bool, true)<br/>    protocol       = optional(string, "tcp")<br/>    wan_port       = string<br/>    wan_interface  = optional(string, "both")<br/>    wan_ip_address = optional(string)<br/>    forward_ip     = string<br/>    forward_port   = optional(string)<br/>    logging        = optional(bool)<br/>    destination_ips = optional(list(object({<br/>      destination_ip = string<br/>      interface      = string<br/>    })), [])<br/>  }))</pre> | `{}` | no |
| <a name="input_zone_ids"></a> [zone\_ids](#input\_zone\_ids) | IDs of firewall zones that this configuration creates, by zone name (for example the zone\_id output of terraform-unifi-network). A zone named in a policy is looked up in the controller unless it is here: a zone created in the same run does not exist yet at plan time. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_group_ids"></a> [group\_ids](#output\_group\_ids) | ID of each firewall group, by key. |
| <a name="output_policy_ids"></a> [policy\_ids](#output\_policy\_ids) | ID of each firewall policy, by key. |
| <a name="output_port_forward_ids"></a> [port\_forward\_ids](#output\_port\_forward\_ids) | ID of each port forward, by key. |
| <a name="output_zone_ids"></a> [zone\_ids](#output\_zone\_ids) | ID of every zone named by a policy, by zone name: the ones given in zone\_ids and the ones found in the controller. |
<!-- END_TF_DOCS -->
