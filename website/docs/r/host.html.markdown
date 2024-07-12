---
layout: "zabbix"
page_title: "Zabbix: zabbix_host"
sidebar_current: "docs-zabbix-resource-host"
description: |-
  Provides a zabbix host resource. This can be used to create and manage Zabbix Host.
---

# zabbix_host

An [host](https://www.zabbix.com/documentation/current/manual/api/reference/host) is typically a device to monitor.

## Example Usage

Create a new host (agent-based)

```hcl
resource "zabbix_host_group" "demo_group" {
  name = "Template demo group"
}

resource "zabbix_host" "demo_host" {
  host = "127.0.0.1"
  name = "the best name"
  interfaces {
    ip = "127.0.0.1"
    main = true
  }
  groups = ["Linux servers", zabbix_host_group.demo_group.name]
  templates = ["Template ICMP Ping"]
}
```

Create a new SNMP host

```hcl
resource "zabbix_host" "demo_host" {
  host      = "cisco-switch1"
  name      = "Cisco Switch one"
  groups    = ["Network devices"]
  templates = ["Cisco IOS by SNMP"]

  interfaces {
    ip   = "10.0.0.123"
    type = "snmp"
    port = 161
    main = true

    details {
      version   = 2
      community = "my_cisco_community"
    }
  }
}
```

## Argument Reference

The following arguments are supported:

* `host` - (Required) Technical name of the host.
* `name` - (Required) Visible name of the host.
* `monitored` - (Optional) Whether the host is monitored or not. Can be `true` (default, monitored), `false` (not monitored).
* `interfaces` - (Required, Multiple, Min: 1)  List of the host interfaces. Note that any changes to interface will trigger recreate.
  * `main` - (Required) Define if it is the default interface or not. Can be `true` (default, is default interface), `false` (not default interface).
  * `dns` - (Optional) Interface DNS name.
  * `ip` - (Optional) Interface IP address
  * `port` - (Optional) TCP/UDP port number of agent. Default is `10050`.
  * `type` - (Optional) Interface type. Can be `agent` (default), `snmp`, `ipmi`, `jmx`.
  * `details` - (Required if type is `snmp`) SNMP details
    * `version` - (Optional) SNMP version. Default is `2`
    * `community` - (Optional) SNMP community.
* `groups` - (Optional) List of host group names the host belongs to.
* `templates` - (Optional) List of template names to link to the host.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `host_id` - The zabbix host ID
* `interfaces`
  * `interface_id` - The zabbix host interface ID
