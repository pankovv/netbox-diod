from cryptography.fernet import Fernet, InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from netbox.plugins import get_plugin_config


class EncryptedTextField(models.TextField):
    prefix = "fernet$"

    def _fernet(self):
        key = get_plugin_config("netbox_snmp_discovery", "encryption_key")
        if not key:
            raise ImproperlyConfigured(
                "PLUGINS_CONFIG['netbox_snmp_discovery']['encryption_key'] is required"
            )
        try:
            return Fernet(key.encode() if isinstance(key, str) else key)
        except (TypeError, ValueError) as exc:
            raise ImproperlyConfigured(
                "SNMP Discovery encryption_key must be a Fernet key"
            ) from exc

    def from_db_value(self, value, expression, connection):
        if value in (None, "") or not value.startswith(self.prefix):
            return value
        try:
            return self._fernet().decrypt(
                value[len(self.prefix):].encode()
            ).decode()
        except InvalidToken as exc:
            raise ImproperlyConfigured(
                "Unable to decrypt an SNMP credential; verify encryption_key"
            ) from exc

    def to_python(self, value):
        return value

    def get_prep_value(self, value):
        if value in (None, "") or (
            isinstance(value, str) and value.startswith(self.prefix)
        ):
            return value
        token = self._fernet().encrypt(str(value).encode()).decode()
        return self.prefix + token
