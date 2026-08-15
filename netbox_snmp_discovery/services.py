import asyncio
import concurrent.futures
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone
from easysnmp import Session
from ipam.choices import IPAddressStatusChoices
from ipam.models import IPAddress, Prefix
from dcim.models import (
    Device, DeviceRole, DeviceType, Interface, Manufacturer, Site,
)
from netbox.plugins import get_plugin_config
from .models import DiscoveryLog, DiscoveryRun, SNMPCredential


SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = ".1.3.6.1.2.1.1.2.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"
IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
IP_IF_INDEX = ".1.3.6.1.2.1.4.20.1.2"
ENTITY_SERIAL = ".1.3.6.1.2.1.47.1.1.1.1.11"


@dataclass
class Target:
    ip_object: IPAddress
    prefix: Prefix
    site: Site


@dataclass
class SNMPResult:
    address: str
    name: str
    description: str
    object_id: str
    serial: str
    interface_index: str
    interface_name: str


class DiscoveryService:
    def __init__(self, run_id, credential_id):
        self.run = DiscoveryRun.objects.get(pk=run_id)
        self.credential = SNMPCredential.objects.get(pk=credential_id)
        self.ping_timeout = min(
            int(get_plugin_config("netbox_snmp_discovery", "ping_timeout")), 5
        )
        self.snmp_timeout = min(
            int(get_plugin_config("netbox_snmp_discovery", "snmp_timeout")), 5
        )
        self.workers = max(
            1, int(get_plugin_config("netbox_snmp_discovery", "workers"))
        )
        self.tcp_port = int(
            get_plugin_config("netbox_snmp_discovery", "tcp_fallback_port")
        )
        self.role_name = get_plugin_config(
            "netbox_snmp_discovery", "device_role"
        )

    def log(self, message, level="info", prefix="", address=None):
        DiscoveryLog.objects.create(
            run=self.run, level=level, prefix=str(prefix) if prefix else "",
            address=address, message=message,
        )

    def run(self):
        self.run.status = "running"
        self.run.started = timezone.now()
        self.run.save(update_fields=("status", "started"))
        try:
            targets = self._targets()
            self.run.prefixes_total = len({target.prefix.pk for target in targets})
            self.run.save(update_fields=("prefixes_total",))
            self.log(f"Loaded {len(targets)} existing IP addresses.")

            reachable = asyncio.run(self._check_reachability(targets))
            self._update_ip_statuses(targets, reachable)
            self.run.progress = 50
            self.run.save(update_fields=("progress",))

            active = [
                target for target in targets
                if str(target.ip_object.address.ip) in reachable
            ]
            self._discover_devices(active)
            self.run.status = "completed"
            self.run.progress = 100
            self.run.completed = timezone.now()
            self.run.save(
                update_fields=("status", "progress", "completed")
            )
            self.log("Discovery completed.")
        except Exception as exc:
            self.run.status = "failed"
            self.run.completed = timezone.now()
            self.run.save(update_fields=("status", "completed"))
            self.log(f"Discovery failed: {exc}", "error")
            raise

    def _targets(self):
        prefixes = list(
            Prefix.objects.filter(tags__name__exact="discovery")
            .select_related("tenant", "scope_type")
            .prefetch_related("tags")
            .order_by("prefix")
        )
        selected = {}
        for prefix in sorted(prefixes, key=lambda obj: obj.prefix.prefixlen):
            if prefix.tenant_id is None:
                self.log(
                    "Skipped: Prefix tenant is required.", "error", prefix.prefix
                )
                continue
            if not isinstance(prefix.scope, Site):
                self.log(
                    "Skipped: Prefix scope must be a Site in NetBox 4.3.",
                    "error", prefix.prefix,
                )
                continue
            queryset = IPAddress.objects.filter(
                address__net_contained_or_equal=str(prefix.prefix)
            )
            for ip_object in queryset:
                address = str(ip_object.address.ip)
                selected[address] = Target(ip_object, prefix, prefix.scope)
        return list(selected.values())

    async def _probe(self, address, semaphore):
        async with semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ping", "-n", "-c", "1", "-W", str(self.ping_timeout),
                    address,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                if await process.wait() == 0:
                    return address, True
            except FileNotFoundError:
                pass
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, self.tcp_port),
                    timeout=self.ping_timeout,
                )
                writer.close()
                await writer.wait_closed()
                return address, True
            except (OSError, asyncio.TimeoutError):
                return address, False

    async def _check_reachability(self, targets):
        semaphore = asyncio.Semaphore(self.workers)
        results = await asyncio.gather(*(
            self._probe(str(target.ip_object.address.ip), semaphore)
            for target in targets
        ))
        return {address for address, available in results if available}

    def _update_ip_statuses(self, targets, reachable):
        active = 0
        for target in targets:
            ip_object = target.ip_object
            address = str(ip_object.address.ip)
            if address in reachable:
                active += 1
                if ip_object.status != IPAddressStatusChoices.STATUS_ACTIVE:
                    ip_object.status = IPAddressStatusChoices.STATUS_ACTIVE
                    ip_object.save(update_fields=("status",))
                    self.log(
                        "IP status changed to active.", prefix=target.prefix.prefix,
                        address=address,
                    )
            elif ip_object.status == IPAddressStatusChoices.STATUS_ACTIVE:
                ip_object.status = IPAddressStatusChoices.STATUS_DEPRECATED
                ip_object.save(update_fields=("status",))
                self.log(
                    "IP status changed to deprecated.", "warning",
                    target.prefix.prefix, address,
                )
        self.run.addresses_checked = len(targets)
        self.run.addresses_active = active
        self.run.save(
            update_fields=("addresses_checked", "addresses_active")
        )

    @staticmethod
    def _oid_suffix(item, marker):
        return item.oid_index or item.oid.rsplit(marker, 1)[-1]

    def _snmp_session(self, address):
        return Session(
            hostname=address,
            version=3,
            security_username=self.credential.username,
            auth_password=self.credential.auth_key,
            privacy_password=self.credential.priv_key,
            auth_protocol=self.credential.auth_protocol,
            privacy_protocol=self.credential.priv_protocol,
            security_level="auth_with_privacy",
            timeout=self.snmp_timeout,
            retries=0,
            use_numeric=True,
        )

    def _snmp_get(self, target):
        address = str(target.ip_object.address.ip)
        session = self._snmp_session(address)
        values = session.get([SYS_NAME, SYS_DESCR, SYS_OBJECT_ID])
        name = values[0].value.strip()
        description = values[1].value.strip()
        object_id = values[2].value.strip()
        if not name or not description:
            raise RuntimeError("empty sysName/sysDescr")

        serial = ""
        try:
            for item in session.walk(ENTITY_SERIAL):
                value = item.value.strip()
                if value and not value.lower().startswith("nosuch"):
                    serial = value[:50]
                    break
        except Exception:
            pass

        interfaces = {}
        try:
            for item in session.walk(IF_DESCR):
                index = self._oid_suffix(item, ".1.2.")
                interfaces[str(index)] = item.value.strip()
        except Exception:
            pass

        interface_index = ""
        try:
            for item in session.walk(IP_IF_INDEX):
                item_address = self._oid_suffix(item, ".1.2.")
                if item_address == address:
                    interface_index = str(item.value)
                    break
        except Exception:
            pass
        interface_name = interfaces.get(interface_index, "SNMP Discovery")
        return SNMPResult(
            address, name[:64], description, object_id, serial,
            interface_index, interface_name[:64],
        )

    def _discover_devices(self, targets):
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:
            futures = {
                executor.submit(self._snmp_get, target): target
                for target in targets
            }
            total = len(futures)
            for processed, future in enumerate(
                concurrent.futures.as_completed(futures), start=1
            ):
                target = futures[future]
                address = str(target.ip_object.address.ip)
                try:
                    result = future.result()
                except Exception as exc:
                    self.log(
                        f"SNMPv3 failed: {exc}", "warning",
                        target.prefix.prefix, address,
                    )
                else:
                    self._upsert_device(target, result)
                self.run.progress = 50 + int(49 * processed / max(total, 1))
                self.run.save(update_fields=("progress",))

    def _device_type(self, object_id):
        if object_id:
            matched = DeviceType.objects.filter(
                custom_field_data__snmp_sysobjectid=object_id
            ).first()
            if matched:
                return matched
        manufacturer, _ = Manufacturer.objects.get_or_create(
            name="Generic", defaults={"slug": "generic"}
        )
        device_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer,
            model="Unknown (SNMP)",
            defaults={"slug": "unknown-snmp"},
        )
        return device_type

    def _find_device(self, target, result):
        if result.serial:
            device = Device.objects.filter(serial=result.serial).first()
            if device:
                return device
        return Device.objects.filter(
            name=result.name, site=target.site
        ).first()

    @transaction.atomic
    def _upsert_device(self, target, result):
        role = (
            DeviceRole.objects.filter(name=self.role_name).first()
            or DeviceRole.objects.get(slug=self.role_name)
        )
        device_type = self._device_type(result.object_id)
        device = self._find_device(target, result)
        created = device is None
        assigned = target.ip_object.assigned_object
        if assigned and (
            created or getattr(assigned, "device_id", None) != device.pk
        ):
            self.log(
                f"IP assignment conflict with {assigned}.", "error",
                target.prefix.prefix, result.address,
            )
            return
        if created:
            device = Device(
                name=result.name, serial=result.serial,
                site=target.site, tenant=target.prefix.tenant,
                role=role, device_type=device_type, status="active",
            )
        else:
            if device.site_id != target.site.pk:
                self.log(
                    f"Site conflict: device remains at {device.site}.",
                    "error", target.prefix.prefix, result.address,
                )
                return
            device.name = result.name
            device.device_type = device_type
            device.tenant = target.prefix.tenant
            if result.serial:
                device.serial = result.serial
        device.full_clean()
        device.save()

        interface, _ = Interface.objects.get_or_create(
            device=device, name=result.interface_name,
            defaults={"type": "other", "enabled": True},
        )
        ip_object = target.ip_object
        ip_object.assigned_object = interface
        ip_object.status = IPAddressStatusChoices.STATUS_ACTIVE
        ip_object.save()
        device.primary_ip4 = ip_object
        device.save(update_fields=("primary_ip4",))

        field = "devices_created" if created else "devices_updated"
        setattr(self.run, field, getattr(self.run, field) + 1)
        self.run.save(update_fields=(field,))
        action = "Created" if created else "Updated"
        self.log(
            f"{action} device {device.name}; primary IP assigned to "
            f"{interface.name}.",
            prefix=target.prefix.prefix, address=result.address,
        )
