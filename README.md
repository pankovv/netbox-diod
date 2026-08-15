# NetBox SNMP Discovery

A NetBox 4.3 plugin that checks existing IP addresses and discovers devices
with SNMPv3.

## Workflow

1. Selects only IPAM prefixes tagged exactly `discovery`.
2. Requires every selected prefix to have a tenant and a Site scope.
3. Checks only IP addresses that already exist in NetBox. It never creates
   unknown addresses.
4. Marks reachable addresses `active`; previously active unreachable
   addresses become `deprecated`.
5. Queries reachable addresses with the SNMPv3 credential selected by the
   operator.
6. Creates or updates a device, inherits tenant and site from its prefix,
   assigns the existing IP to the discovered interface, and makes it Primary
   IPv4.
7. Stores progress and an event log for every background discovery run.

Credentials are encrypted at rest with Fernet. The encryption key is kept in
NetBox configuration, separately from the database.

## Install

```bash
sudo /opt/netbox/venv/bin/pip install \
  git+https://github.com/pankovv/netbox-diod.git
```

Generate an encryption key once:

```bash
/opt/netbox/venv/bin/python -c \
  "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add the plugin to `/opt/netbox/netbox/netbox/configuration.py`:

```python
PLUGINS = [
    # Other plugins...
    "netbox_snmp_discovery",
]

PLUGINS_CONFIG = {
    # Other plugin configuration...
    "netbox_snmp_discovery": {
        "encryption_key": "PASTE_THE_GENERATED_FERNET_KEY_HERE",
        "ping_timeout": 2,
        "snmp_timeout": 5,
        "workers": 16,
        "device_role": "net_automate",
        "tcp_fallback_port": 161,
    },
}
```

Keep `configuration.py` readable only by the NetBox service account and do
not commit the encryption key. Losing or changing the key makes saved
credentials unreadable.

Apply migrations and restart NetBox:

```bash
sudo /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate
sudo systemctl restart netbox netbox-rq
```

## Prepare NetBox

1. Create the device role `net_automate` (or change `device_role`).
2. Add the exact, case-sensitive tag `discovery` to target prefixes.
3. Set a tenant on each target prefix.
4. In NetBox 4.3, set the prefix Scope Type to **Site** and select a Site.
5. Create the IP addresses to check inside those prefixes. The plugin
   intentionally does not generate every host address in a subnet.
6. Grant users the plugin permissions for SNMP credentials and discovery runs.

## Use

Open **Plugins → SNMP Discovery**:

- create a credential under **SNMP Credentials**;
- choose it on **Run Discovery**;
- click **Start Discovery**;
- follow status and logs under **Discovery Runs**.

The task is executed by NetBox's native RQ background worker, so the web
request is not blocked. The run detail page refreshes while work is pending.

## SNMPv3

Credentials support:

- authentication: SHA or MD5;
- privacy: AES or DES;
- security level: authPriv.

SNMP timeout is capped at five seconds. Authentication failures and timeouts
are logged per address and do not stop the run.

The plugin reads:

- `sysName.0`;
- `sysDescr.0`;
- `sysObjectID.0`;
- ENTITY-MIB serial numbers;
- IF-MIB interface names;
- IP-MIB address-to-ifIndex mapping.

For DeviceType matching, create a NetBox custom field named
`snmp_sysobjectid` for Device Types and store the numeric sysObjectID in it.
If no match exists, the plugin uses **Generic / Unknown (SNMP)**.

Devices are matched first by non-empty serial number, then by `name + site`.
If a serial-matched device belongs to another site, it is not moved and a
conflict is written to the discovery log.

## Development checks

```bash
python -m compileall -q netbox_snmp_discovery
python -m build
```
