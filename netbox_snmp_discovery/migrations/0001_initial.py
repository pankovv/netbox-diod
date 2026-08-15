import django.db.models.deletion
from django.conf import settings
import django.core.validators
from django.db import migrations, models

import netbox_snmp_discovery.fields


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="SNMPCredential",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False
                )),
                ("name", models.CharField(max_length=100, unique=True)),
                ("username", models.CharField(max_length=128)),
                ("auth_key", netbox_snmp_discovery.fields.EncryptedTextField(
                    validators=[django.core.validators.MinLengthValidator(8)]
                )),
                ("priv_key", netbox_snmp_discovery.fields.EncryptedTextField(
                    validators=[django.core.validators.MinLengthValidator(8)]
                )),
                ("auth_protocol", models.CharField(
                    choices=[("SHA", "SHA"), ("MD5", "MD5")],
                    default="SHA", max_length=8,
                )),
                ("priv_protocol", models.CharField(
                    choices=[
                        ("AES", "AES-128"),
                        ("AES256", "AES-256"),
                        ("AES256C", "AES-256 (Cisco)"),
                        ("DES", "DES"),
                    ],
                    default="AES", max_length=8,
                )),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="DiscoveryRun",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False
                )),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"), ("running", "Running"),
                        ("completed", "Completed"), ("failed", "Failed"),
                    ], default="pending", max_length=16,
                )),
                ("progress", models.PositiveSmallIntegerField(default=0)),
                ("prefixes_total", models.PositiveIntegerField(default=0)),
                ("addresses_checked", models.PositiveIntegerField(default=0)),
                ("addresses_active", models.PositiveIntegerField(default=0)),
                ("devices_created", models.PositiveIntegerField(default=0)),
                ("devices_updated", models.PositiveIntegerField(default=0)),
                ("started", models.DateTimeField(blank=True, null=True)),
                ("completed", models.DateTimeField(blank=True, null=True)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+", to=settings.AUTH_USER_MODEL,
                )),
                ("credential", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="runs", to="netbox_snmp_discovery.snmpcredential",
                )),
            ],
            options={"ordering": ("-created",)},
        ),
        migrations.CreateModel(
            name="DiscoveryLog",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False
                )),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("level", models.CharField(
                    choices=[("info", "Info"), ("warning", "Warning"), ("error", "Error")],
                    default="info", max_length=8,
                )),
                ("prefix", models.CharField(blank=True, max_length=64)),
                ("address", models.GenericIPAddressField(blank=True, null=True)),
                ("message", models.TextField()),
                ("run", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="logs", to="netbox_snmp_discovery.discoveryrun",
                )),
            ],
            options={"ordering": ("timestamp", "pk")},
        ),
    ]
