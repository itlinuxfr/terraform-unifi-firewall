variable "name_prefix" {
  description = "Prefix added to the name of every group, and to the name of every policy and port forward that has no name of its own. For example k8s-prod- gives k8s-prod-nodes."
  type        = string
  default     = ""
  nullable    = false
}

variable "zone_ids" {
  description = "IDs of firewall zones that this configuration creates, by zone name (for example the zone_id output of terraform-unifi-network). A zone named in a policy is looked up in the controller unless it is here: a zone created in the same run does not exist yet at plan time."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "network_ids" {
  description = "IDs of networks that policies can match, by key (for example the network_id output of terraform-unifi-network). A policy names the key, not the ID."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "groups" {
  description = <<-EOT
    Firewall groups, by key. A policy refers to a group by its key.
    - type: address-group (IPv4), ipv6-address-group or port-group.
    - members: IP addresses or CIDRs for an address group (a single address is written without /32: the controller refuses it), ports or ranges such as 8000-8100 for a port group.
    - name: name in the controller. Defaults to name_prefix followed by the key.
  EOT
  type = map(object({
    type    = optional(string, "address-group")
    members = list(string)
    name    = optional(string)
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for group in values(var.groups) : contains(["address-group", "ipv6-address-group", "port-group"], group.type)])
    error_message = "A group type must be address-group, ipv6-address-group or port-group."
  }

  validation {
    condition     = alltrue([for group in values(var.groups) : length(group.members) >= 1])
    error_message = "A group needs at least one member."
  }

  validation {
    condition = alltrue([
      for group in values(var.groups) :
      group.type != "address-group" ? true : alltrue([
        for member in group.members :
        !strcontains(member, ":") && !endswith(member, "/32") && (can(cidrhost(member, 0)) || can(cidrhost("${member}/32", 0)))
      ])
    ])
    error_message = "Members of an address-group must be IPv4 addresses or CIDRs. Write a single address without /32: the controller refuses the /32 notation."
  }

  validation {
    condition = alltrue([
      for group in values(var.groups) :
      group.type != "ipv6-address-group" ? true : alltrue([
        for member in group.members :
        strcontains(member, ":") && (can(cidrhost(member, 0)) || can(cidrhost("${member}/128", 0)))
      ])
    ])
    error_message = "Members of an ipv6-address-group must be IPv6 addresses or CIDRs."
  }

  validation {
    condition = alltrue([
      for group in values(var.groups) :
      group.type != "port-group" ? true : alltrue([
        for member in group.members : can(regex("^[0-9]+(-[0-9]+)?$", member)) && alltrue([for port in split("-", member) : tonumber(port) >= 1 && tonumber(port) <= 65535])
      ])
    ])
    error_message = "Members of a port-group must be ports or ranges between 1 and 65535, such as 443 or 8000-8100."
  }
}

variable "policies" {
  description = <<-EOT
    Zone-based firewall policies, by key.
    - action: ALLOW, BLOCK or REJECT.
    - protocol: all, tcp, udp, tcp_udp, icmp or icmpv6. Required when ports or port_group are used.
    - create_allow_respond: also allow the return traffic. Null means true for an ALLOW policy (except icmp, which the controller refuses), and the controller value otherwise.
    - source and destination: zone is a zone name. Match at most one of networks (keys of network_ids), ip_group (key of groups), ips or regions
      (two-letter country codes: the controller only accepts them on an external zone). Match ports with ports ("53", "80,443", "8000-8100") or with port_group (key of groups).
      With nothing set, the whole zone matches.
    - enabled, logging, ip_version, description, name: null keeps the controller value or the default (name is name_prefix followed by the key).
    The controller adds a policy at the end of its pair of zones and offers no way to reorder it: see the README.
  EOT
  type = map(object({
    name                 = optional(string)
    description          = optional(string)
    action               = string
    protocol             = optional(string)
    ip_version           = optional(string)
    create_allow_respond = optional(bool)
    logging              = optional(bool)
    enabled              = optional(bool)
    source = object({
      zone       = string
      networks   = optional(list(string), [])
      ip_group   = optional(string)
      ips        = optional(list(string), [])
      regions    = optional(list(string), [])
      ports      = optional(string)
      port_group = optional(string)
    })
    destination = object({
      zone       = string
      networks   = optional(list(string), [])
      ip_group   = optional(string)
      ips        = optional(list(string), [])
      regions    = optional(list(string), [])
      ports      = optional(string)
      port_group = optional(string)
    })
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for policy in values(var.policies) : contains(["ALLOW", "BLOCK", "REJECT"], policy.action)])
    error_message = "A policy action must be ALLOW, BLOCK or REJECT."
  }

  validation {
    condition     = alltrue([for policy in values(var.policies) : policy.protocol == null ? true : contains(["all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6"], policy.protocol)])
    error_message = "A policy protocol must be all, tcp, udp, tcp_udp, icmp or icmpv6."
  }

  validation {
    condition     = alltrue([for policy in values(var.policies) : policy.ip_version == null ? true : contains(["BOTH", "IPV4", "IPV6"], policy.ip_version)])
    error_message = "A policy ip_version must be BOTH, IPV4 or IPV6."
  }

  validation {
    condition = alltrue([
      for policy in values(var.policies) :
      policy.create_allow_respond != true || !contains(["icmp", "icmpv6"], coalesce(policy.protocol, "all"))
    ])
    error_message = "create_allow_respond cannot be true for an icmp or icmpv6 policy: the controller refuses it."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      (length(endpoint.networks) > 0 ? 1 : 0) + (endpoint.ip_group != null ? 1 : 0) + (length(endpoint.ips) > 0 ? 1 : 0) + (length(endpoint.regions) > 0 ? 1 : 0) <= 1
    ])
    error_message = "An endpoint matches at most one of networks, ip_group, ips and regions."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      endpoint.ports == null || endpoint.port_group == null
    ])
    error_message = "An endpoint matches ports with ports or with port_group, not both."
  }

  validation {
    condition = alltrue([
      for policy in values(var.policies) :
      alltrue([
        for endpoint in [policy.source, policy.destination] :
        (endpoint.ports == null && endpoint.port_group == null) || contains(["tcp", "udp", "tcp_udp"], coalesce(policy.protocol, "all"))
      ])
    ])
    error_message = "Matching ports needs protocol tcp, udp or tcp_udp."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      endpoint.ports == null ? true : (
        can(regex("^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$", endpoint.ports)) &&
        alltrue([for port in flatten([for part in split(",", endpoint.ports) : split("-", part)]) : tonumber(port) >= 1 && tonumber(port) <= 65535])
      )
    ])
    error_message = "ports must be a port, a range or a comma-separated list between 1 and 65535, such as 53, 80,443 or 8000-8100."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      alltrue([for code in endpoint.regions : can(regex("^[A-Z]{2}$", code))])
    ])
    error_message = "regions must be two-letter uppercase ISO country codes, such as FR."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      alltrue([for key in endpoint.networks : contains(keys(var.network_ids), key)])
    ])
    error_message = "A policy matches a network that is not a key of network_ids."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      endpoint.ip_group == null ? true : (
        contains(keys(var.groups), endpoint.ip_group) &&
        contains(["address-group", "ipv6-address-group"], try(var.groups[endpoint.ip_group].type, ""))
      )
    ])
    error_message = "ip_group must be the key of an address-group or ipv6-address-group in groups."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      endpoint.port_group == null ? true : (
        contains(keys(var.groups), endpoint.port_group) &&
        try(var.groups[endpoint.port_group].type, "") == "port-group"
      )
    ])
    error_message = "port_group must be the key of a port-group in groups."
  }

  validation {
    condition = alltrue([
      for endpoint in flatten([for policy in values(var.policies) : [policy.source, policy.destination]]) :
      trimspace(endpoint.zone) != ""
    ])
    error_message = "A policy endpoint needs a zone name."
  }
}

variable "port_forwards" {
  description = <<-EOT
    Port forwards from the WAN to an address of the LAN, by key.
    - protocol: tcp, udp or tcp_udp.
    - wan_port, forward_port: a port or a range. forward_port defaults to wan_port.
    - wan_interface: wan, wan2 or both.
    - wan_ip_address: WAN address to match. Null matches any.
    - destination_ips: extra destination address and interface pairs, for several WANs.
    - enabled: the provider deprecates this argument but still needs it: a rule created without it is created disabled, which never opens a port by mistake.
      The module sets it, so Terraform prints a deprecation warning.
    The UniFi gateway also creates the zone policy that lets the traffic in: the policies of this module are evaluated before it.
  EOT
  type = map(object({
    name           = optional(string)
    enabled        = optional(bool, true)
    protocol       = optional(string, "tcp")
    wan_port       = string
    wan_interface  = optional(string, "both")
    wan_ip_address = optional(string)
    forward_ip     = string
    forward_port   = optional(string)
    logging        = optional(bool)
    destination_ips = optional(list(object({
      destination_ip = string
      interface      = string
    })), [])
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for forward in values(var.port_forwards) : contains(["tcp", "udp", "tcp_udp"], forward.protocol)])
    error_message = "A port forward protocol must be tcp, udp or tcp_udp."
  }

  validation {
    condition     = alltrue([for forward in values(var.port_forwards) : contains(["wan", "wan2", "both"], forward.wan_interface)])
    error_message = "wan_interface must be wan, wan2 or both."
  }

  validation {
    condition = alltrue([
      for forward in values(var.port_forwards) :
      alltrue([
        for ports in compact([forward.wan_port, forward.forward_port]) :
        can(regex("^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$", ports)) &&
        alltrue([for port in flatten([for part in split(",", ports) : split("-", part)]) : tonumber(port) >= 1 && tonumber(port) <= 65535])
      ])
    ])
    error_message = "wan_port and forward_port must be ports or ranges between 1 and 65535, such as 443 or 8000-8100."
  }

  validation {
    condition     = alltrue([for forward in values(var.port_forwards) : !strcontains(forward.forward_ip, ":") && can(cidrhost("${forward.forward_ip}/32", 0))])
    error_message = "forward_ip must be an IPv4 address without a prefix length."
  }

  validation {
    condition     = alltrue([for forward in values(var.port_forwards) : forward.wan_ip_address == null ? true : (forward.wan_ip_address == "any" || (!strcontains(forward.wan_ip_address, ":") && can(cidrhost("${forward.wan_ip_address}/32", 0))))])
    error_message = "wan_ip_address must be any or an IPv4 address."
  }
}
