from django.conf import settings
from django.core.validators import MinLengthValidator
from django.db import models
from django.urls import reverse

from .fields import EncryptedTextField


class SNMPCredential(models.Model):
    AUTH_CHOICES = (("SHA", "SHA"), ("MD5", "MD5"))
    PRIV_CHOICES = (("AES", "AES"), ("DES", "DES"))

    name = models.CharField(max_length=100, unique=True)
    username = models.CharField(max_length=128)
    auth_key = EncryptedTextField(validators=[MinLengthValidator(8)])
    priv_key = EncryptedTextField(validators=[MinLengthValidator(8)])
    auth_protocol = models.CharField(max_length=8, choices=AUTH_CHOICES, default="SHA")
    priv_protocol = models.CharField(max_length=8, choices=PRIV_CHOICES, default="AES")
    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_snmp_discovery:credential_list")


class DiscoveryRun(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    )
    credential = models.ForeignKey(
        SNMPCredential, on_delete=models.PROTECT, related_name="runs"
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+"
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="pending")
    progress = models.PositiveSmallIntegerField(default=0)
    prefixes_total = models.PositiveIntegerField(default=0)
    addresses_checked = models.PositiveIntegerField(default=0)
    addresses_active = models.PositiveIntegerField(default=0)
    devices_created = models.PositiveIntegerField(default=0)
    devices_updated = models.PositiveIntegerField(default=0)
    started = models.DateTimeField(null=True, blank=True)
    completed = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created",)

    def __str__(self):
        return f"Discovery run {self.pk}"

    def get_absolute_url(self):
        return reverse(
            "plugins:netbox_snmp_discovery:run_detail", args=[self.pk]
        )


class DiscoveryLog(models.Model):
    LEVEL_CHOICES = (
        ("info", "Info"), ("warning", "Warning"), ("error", "Error")
    )
    run = models.ForeignKey(
        DiscoveryRun, on_delete=models.CASCADE, related_name="logs"
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=8, choices=LEVEL_CHOICES, default="info")
    prefix = models.CharField(max_length=64, blank=True)
    address = models.GenericIPAddressField(null=True, blank=True)
    message = models.TextField()

    class Meta:
        ordering = ("timestamp", "pk")
