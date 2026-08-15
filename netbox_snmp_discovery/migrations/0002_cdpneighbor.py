import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("dcim", "0208_devicerole_uniqueness"),
        ("netbox_snmp_discovery", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="CDPNeighbor",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False
                )),
                ("remote_device_name", models.CharField(max_length=128)),
                ("remote_port", models.CharField(blank=True, max_length=128)),
                ("remote_platform", models.CharField(blank=True, max_length=128)),
                ("remote_address", models.GenericIPAddressField(blank=True, null=True)),
                ("active", models.BooleanField(default=True)),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("local_device", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="cdp_neighbors", to="dcim.device",
                )),
                ("local_interface", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="cdp_neighbors", to="dcim.interface",
                )),
                ("remote_device", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="discovered_as_cdp_neighbor", to="dcim.device",
                )),
            ],
            options={
                "ordering": (
                    "local_device__name", "local_interface__name",
                    "remote_device_name",
                ),
            },
        ),
        migrations.AddConstraint(
            model_name="cdpneighbor",
            constraint=models.UniqueConstraint(
                fields=(
                    "local_device", "local_interface",
                    "remote_device_name", "remote_port",
                ),
                name="netbox_snmp_discovery_unique_cdp_neighbor",
            ),
        ),
    ]
