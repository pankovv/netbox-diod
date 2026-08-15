# NetBox SNMP discovery

Discovers network devices with SNMPv2c and imports them directly into a local
NetBox installation.

The scanner:

- probes every host in an IPv4 network with an isolated timeout;
- creates or updates devices by SNMP system name;
- creates interfaces from IF-MIB;
- creates IP addresses from IP-MIB;
- assigns each IP to the matching interface using SNMP ifIndex;
- sets the discovered address as the device Primary IPv4.

## Requirements

- NetBox installed locally (tested with NetBox 4.3);
- Python environment used by NetBox;
- EasySNMP installed (the default configuration reuses the Diode collection
  environment at `/opt/diode/collection/venv`);
- an existing NetBox site and device role;
- SNMPv2c enabled on target devices.

## Run

```bash
sudo -u netbox \
  SNMP_NETWORK=10.0.1.0/24 \
  SNMP_COMMUNITY=public \
  NETBOX_SITE=msk \
  NETBOX_DEVICE_ROLE=net_automate \
  /opt/netbox/venv/bin/python scan_network_into_netbox.py
```

Configuration variables:

| Variable | Default |
| --- | --- |
| `SNMP_NETWORK` | `10.0.1.0/24` |
| `SNMP_COMMUNITY` | `public` |
| `NETBOX_SITE` | `msk` |
| `NETBOX_DEVICE_ROLE` | `net_automate` |
| `NETBOX_PATH` | `/opt/netbox/netbox` |
| `DIODE_SITE_PACKAGES` | `/opt/diode/collection/venv/lib/python3.12/site-packages` |

Use a read-only SNMP community and keep its value outside version control.

## Current behavior

Cisco devices are assigned to manufacturer `Cisco`; other responding devices
use manufacturer `Unknown`. A device type named `unknown` is created per
manufacturer when it does not already exist.

This implementation writes through the local NetBox Django ORM. It is useful
with NetBox/Diode combinations where the installed Diode plugin does not expose
the bulk apply endpoints required by newer Diode server releases.
