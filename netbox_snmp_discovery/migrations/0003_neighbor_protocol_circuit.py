import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("circuits", "0052_extend_circuit_abs_distance_upper_limit"),
        ("netbox_snmp_discovery", "0002_cdpneighbor"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="cdpneighbor",
            name="netbox_snmp_discovery_unique_cdp_neighbor",
        ),
        migrations.AddField(
            model_name="cdpneighbor",
            name="protocol",
            field=models.CharField(
                choices=(("cdp", "CDP"), ("lldp", "LLDP")),
                default="cdp", max_length=4,
            ),
        ),
        migrations.AddField(
            model_name="cdpneighbor",
            name="circuit",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="discovered_neighbors", to="circuits.circuit",
            ),
        ),
        migrations.AddConstraint(
            model_name="cdpneighbor",
            constraint=models.UniqueConstraint(
                fields=(
                    "protocol", "local_device", "local_interface",
                    "remote_device_name", "remote_port",
                ),
                name="netbox_snmp_discovery_unique_neighbor",
            ),
        ),
    ]
