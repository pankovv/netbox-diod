from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem


menu = PluginMenu(
    label="SNMP Discovery",
    icon_class="mdi mdi-radar",
    groups=(
        ("Discovery", (
            PluginMenuItem(
                link="plugins:netbox_snmp_discovery:run",
                link_text="Run Discovery",
                permissions=("netbox_snmp_discovery.add_discoveryrun",),
            ),
            PluginMenuItem(
                link="plugins:netbox_snmp_discovery:run_list",
                link_text="Discovery Runs",
                permissions=("netbox_snmp_discovery.view_discoveryrun",),
            ),
            PluginMenuItem(
                link="plugins:netbox_snmp_discovery:neighbor_list",
                link_text="CDP Neighbors",
                permissions=("netbox_snmp_discovery.view_cdpneighbor",),
            ),
        )),
        ("Configuration", (
            PluginMenuItem(
                link="plugins:netbox_snmp_discovery:credential_list",
                link_text="SNMP Credentials",
                permissions=("netbox_snmp_discovery.view_snmpcredential",),
                buttons=(
                    PluginMenuButton(
                        link="plugins:netbox_snmp_discovery:credential_add",
                        title="Add credential",
                        icon_class="mdi mdi-plus-thick",
                        permissions=("netbox_snmp_discovery.add_snmpcredential",),
                    ),
                ),
            ),
        )),
    ),
)
