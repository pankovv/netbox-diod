import asyncio
import concurrent.futures
import ipaddress
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
from django.utils.text import slugify

from .models import CDPNeighbor, DiscoveryLog, DiscoveryRun, SNMPCredential


SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = ".1.3.6.1.2.1.1.2.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"
IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
IP_IF_INDEX = ".1.3.6.1.2.1.4.20.1.2"
ENTITY_SERIAL = ".1.3.6.1.2.1.47.1.1.1.1.11"
ENTITY_MFG = ".1.3.6.1.2.1.47.1.1.1.1.12"
ENTITY_MODEL = ".1.3.6.1.2.1.47.1.1.1.1.13"
CDP_ADDRESS = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_DEVICE_ID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT = ".1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_PLATFORM = ".1.3.6.1.4.1.9.9.23.1.2.1.1.8"


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
    manufacturer: str
    model: str
    interfaces: dict
    interface_index: str
    neighbors: list


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
        self.snmp_workers = max(
            1, int(get_plugin_config("netbox_snmp_discovery", "snmp_workers"))
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

    def execute(self):
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

    @staticmethod
    def _table_key(item, base_oid):
        suffix = item.oid.removeprefix(base_oid).strip(".")
        if item.oid_index:
            suffix = ".".join(part for part in (suffix, item.oid_index) if part)
        return suffix

    @staticmethod
    def _decode_cdp_address(value):
        try:
            raw = bytes(ord(character) for character in value)
            return str(ipaddress.ip_address(raw))
        except (ValueError, TypeError):
            return None

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
        manufacturer = ""
        model = ""
        try:
            for item in session.walk(ENTITY_SERIAL):
                value = item.value.strip()
                if value and not value.lower().startswith("nosuch"):
                    serial = value[:50]
                    break
        except Exception:
            pass
        try:
            manufacturers = {
                self._table_key(item, ENTITY_MFG): item.value.strip()
                for item in session.walk(ENTITY_MFG)
            }
            models = {
                self._table_key(item, ENTITY_MODEL): item.value.strip()
                for item in session.walk(ENTITY_MODEL)
            }
            manufacturer = manufacturers.get("1", "") or next(
                (value for value in manufacturers.values() if value), ""
            )
            model = models.get("1", "") or next(
                (value for value in models.values() if value), ""
            )
        except Exception:
            pass
        if not manufacturer:
            manufacturer = (
                "Cisco" if object_id.startswith(".1.3.6.1.4.1.9.")
                or "cisco" in description.lower() else "Unknown"
            )
        if not model:
            model = "Unknown (SNMP)"

        interfaces = {}
        try:
            for item in session.walk(IF_DESCR):
                index = self._table_key(item, IF_DESCR)
                interfaces[str(index)] = item.value.strip()
        except Exception:
            pass

        interface_index = ""
        try:
            for item in session.walk(IP_IF_INDEX):
                item_address = self._table_key(item, IP_IF_INDEX)
                if item_address == address:
                    interface_index = str(item.value)
                    break
        except Exception:
            pass
        neighbors = []
        try:
            device_ids = {
                self._table_key(item, CDP_DEVICE_ID): item.value.strip()
                for item in session.walk(CDP_DEVICE_ID)
            }
            ports = {
                self._table_key(item, CDP_DEVICE_PORT): item.value.strip()
                for item in session.walk(CDP_DEVICE_PORT)
            }
            platforms = {
                self._table_key(item, CDP_PLATFORM): item.value.strip()
                for item in session.walk(CDP_PLATFORM)
            }
            addresses = {
                self._table_key(item, CDP_ADDRESS):
                    self._decode_cdp_address(item.value)
                for item in session.walk(CDP_ADDRESS)
            }
            for key, remote_name in device_ids.items():
                if not remote_name:
                    continue
                neighbors.append({
                    "local_index": key.split(".", 1)[0],
                    "remote_name": remote_name[:128],
                    "remote_port": ports.get(key, "")[:128],
                    "platform": platforms.get(key, "")[:128],
                    "address": addresses.get(key),
                })
        except Exception:
            pass
        return SNMPResult(
            address, name[:64], description, object_id, serial,
            manufacturer[:100], model[:100], interfaces,
            interface_index, neighbors,
        )

    def _discover_devices(self, targets):
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.snmp_workers
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

    def _device_type(self, result):
        if result.object_id:
            matched = DeviceType.objects.filter(
                custom_field_data__snmp_sysobjectid=result.object_id
            ).first()
            if matched:
                return matched
        manufacturer, _ = Manufacturer.objects.get_or_create(
            name=result.manufacturer,
            defaults={"slug": slugify(result.manufacturer)[:100] or "unknown"},
        )
        device_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer,
            model=result.model,
            defaults={"slug": slugify(result.model)[:100] or "unknown-snmp"},
        )
        return device_type

    @staticmethod
    def _interface_type(name):
        lowered = name.lower()
        if "fastethernet" in lowered:
            return "100base-tx"
        if "tengigabit" in lowered:
            return "10gbase-t"
        if "gigabit" in lowered:
            return "1000base-t"
        if "null" in lowered or "loopback" in lowered:
            return "virtual"
        return "other"

    def _find_device(self, target, result):
        device = Device.objects.filter(
            name=result.name, site=target.site
        ).first()
        if device:
            return device
        if result.serial:
            for candidate in Device.objects.filter(serial=result.serial):
                candidate_ip = (
                    str(candidate.primary_ip4.address.ip)
                    if candidate.primary_ip4_id else None
                )
                if candidate_ip == result.address:
                    return candidate
        return None

    @transaction.atomic
    def _upsert_device(self, target, result):
        role = (
            DeviceRole.objects.filter(name=self.role_name).first()
            or DeviceRole.objects.get(slug=self.role_name)
        )
        device_type = self._device_type(result)
        device = self._find_device(target, result)
        created = device is None
        assigned = target.ip_object.assigned_object
        if assigned and (
            created or getattr(assigned, "device_id", None) != device.pk
        ):
            assigned_device = getattr(assigned, "device", None)
            stale_assignment = (
                created
                and assigned_device is not None
                and assigned_device.name != result.name
                and assigned_device.primary_ip4_id != target.ip_object.pk
            )
            if stale_assignment:
                self.log(
                    f"Reclaiming stale IP assignment from "
                    f"{assigned_device.name}.",
                    "warning", target.prefix.prefix, result.address,
                )
            else:
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

        interfaces_by_index = {}
        for index, name in result.interfaces.items():
            if not name:
                continue
            interface, _ = Interface.objects.update_or_create(
                device=device, name=name[:64],
                defaults={
                    "type": self._interface_type(name),
                    "enabled": True,
                },
            )
            interfaces_by_index[index] = interface
        interface = interfaces_by_index.get(result.interface_index)
        if interface is None:
            interface, _ = Interface.objects.get_or_create(
                device=device, name="SNMP Discovery",
                defaults={"type": "virtual", "enabled": True},
            )
        ip_object = target.ip_object
        ip_object.assigned_object = interface
        ip_object.status = IPAddressStatusChoices.STATUS_ACTIVE
        ip_object.save()
        device.primary_ip4 = ip_object
        device.save(update_fields=("primary_ip4",))
        stale_interface = device.interfaces.filter(
            name="SNMP Discovery"
        ).exclude(pk=interface.pk).first()
        if (
            stale_interface
            and not stale_interface.ip_addresses.exists()
            and stale_interface.cable_id is None
        ):
            stale_interface.delete()

        CDPNeighbor.objects.filter(local_device=device).update(active=False)
        for neighbor in result.neighbors:
            local_interface = interfaces_by_index.get(neighbor["local_index"])
            remote_device = Device.objects.filter(
                name__iexact=neighbor["remote_name"], site=target.site
            ).first()
            CDPNeighbor.objects.update_or_create(
                local_device=device,
                local_interface=local_interface,
                remote_device_name=neighbor["remote_name"],
                remote_port=neighbor["remote_port"],
                defaults={
                    "remote_device": remote_device,
                    "remote_platform": neighbor["platform"],
                    "remote_address": neighbor["address"],
                    "active": True,
                },
            )

        field = "devices_created" if created else "devices_updated"
        setattr(self.run, field, getattr(self.run, field) + 1)
        self.run.save(update_fields=(field,))
        action = "Created" if created else "Updated"
        self.log(
            f"{action} device {device.name}; primary IP assigned to "
            f"{interface.name}; {len(interfaces_by_index)} interfaces and "
            f"{len(result.neighbors)} CDP neighbors synchronized.",
            prefix=target.prefix.prefix, address=result.address,
        )
