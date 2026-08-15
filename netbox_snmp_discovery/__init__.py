from netbox.plugins import PluginConfig


class SNMPDiscoveryConfig(PluginConfig):
    name = "netbox_snmp_discovery"
    verbose_name = "SNMP Discovery"
    description = "Discover NetBox IP addresses and devices with SNMPv3"
    version = "0.3.1"
    base_url = "snmp-discovery"
    min_version = "4.3.0"
    max_version = "4.3.99"
    required_settings = ("encryption_key",)
    default_settings = {
        "ping_timeout": 2,
        "snmp_timeout": 5,
        "workers": 16,
        "snmp_workers": 1,
        "device_role": "net_automate",
        "tcp_fallback_port": 161,
        "create_circuits": True,
        "circuit_provider": "SNMP Discovery",
        "circuit_type": "Discovered Link",
    }
    def ready(self):
        super().ready()
        from . import jobs  # noqa: F401


config = SNMPDiscoveryConfig
