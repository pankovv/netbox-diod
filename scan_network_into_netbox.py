import concurrent.futures
import ipaddress
import json
import os
import subprocess
import sys

DIODE_SITE_PACKAGES = os.getenv(
    "DIODE_SITE_PACKAGES",
    "/opt/diode/collection/venv/lib/python3.12/site-packages",
)
NETBOX_PATH = os.getenv("NETBOX_PATH", "/opt/netbox/netbox")
sys.path.insert(0, DIODE_SITE_PACKAGES)

from easysnmp import Session


NETWORK = ipaddress.ip_network(os.getenv("SNMP_NETWORK", "10.0.1.0/24"))
COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
SITE_NAME = os.getenv("NETBOX_SITE", "msk")
ROLE_NAME = os.getenv("NETBOX_DEVICE_ROLE", "net_automate")


def probe(ip):
    try:
        session = Session(hostname=str(ip), community=COMMUNITY, version=2,
                          timeout=1, retries=0)
        name = session.get(".1.3.6.1.2.1.1.5.0").value.strip()
        descr = session.get(".1.3.6.1.2.1.1.1.0").value.strip()
        if not name or not descr or name.lower() in {"nosuchinstance", "nosuchobject"}:
            return None
        return str(ip), name, descr
    except Exception:
        return None


if len(sys.argv) == 3 and sys.argv[1] == "--probe":
    result = probe(sys.argv[2])
    if result:
        print(json.dumps(result))
    raise SystemExit(0 if result else 1)

def isolated_probe(ip):
    try:
        result = subprocess.run(
            ["timeout", "5", sys.executable, __file__, "--probe", str(ip)],
            capture_output=True, text=True, timeout=7,
        )
        if result.returncode == 0 and result.stdout.strip():
            return tuple(json.loads(result.stdout.strip().splitlines()[-1]))
    except Exception:
        pass
    return None

hosts = list(NETWORK.hosts())
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    responsive = [result for result in pool.map(isolated_probe, hosts) if result]

print(f"SNMP_RESPONSES={len(responsive)}")
for ip, name, descr in responsive:
    print(f"SNMP_OK ip={ip} name={name} descr={descr[:100]}")

if not responsive:
    print("SUMMARY created=0 updated=0 errors=0")
    raise SystemExit(0)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
sys.path.insert(0, NETBOX_PATH)
import django
django.setup()

from dcim.models import Device, DeviceRole, DeviceType, Interface, Manufacturer, Site
from ipam.models import IPAddress
from django.db import transaction

site = Site.objects.get(name=SITE_NAME)
role = DeviceRole.objects.get(name=ROLE_NAME)
created_count = updated_count = error_count = 0

for ip, name, descr in responsive:
    try:
        vendor = "Cisco" if "cisco" in descr.lower() else "Unknown"
        manufacturer, _ = Manufacturer.objects.get_or_create(
            name=vendor, defaults={"slug": vendor.lower()}
        )
        dtype, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer, model="unknown", defaults={"slug": "unknown"}
        )
        with transaction.atomic():
            device, made = Device.objects.update_or_create(
                name=name,
                defaults={
                    "site": site,
                    "role": role,
                    "device_type": dtype,
                    "status": "active",
                },
            )
            session = Session(hostname=ip, community=COMMUNITY, version=2,
                              timeout=2, retries=1)
            try:
                names = session.walk(".1.3.6.1.2.1.2.2.1.2")
                interfaces_by_index = {}
                for item in names:
                    ifname = item.value.strip()
                    if not ifname:
                        continue
                    lower = ifname.lower()
                    if "fastethernet" in lower:
                        iface_type = "100base-tx"
                    elif "gigabit" in lower:
                        iface_type = "1000base-t"
                    elif "null" in lower or "loopback" in lower:
                        iface_type = "virtual"
                    else:
                        iface_type = "other"
                    interface, _ = Interface.objects.update_or_create(
                        device=device, name=ifname,
                        defaults={"type": iface_type, "enabled": True},
                    )
                    snmp_index = item.oid_index or item.oid.rsplit(".", 1)[-1]
                    interfaces_by_index[str(snmp_index)] = interface

                target_interface = None
                for item in session.walk(".1.3.6.1.2.1.4.20.1.2"):
                    snmp_address = item.oid_index or item.oid.rsplit(
                        ".1.2.", 1
                    )[-1]
                    if snmp_address == ip:
                        target_interface = interfaces_by_index.get(str(item.value))
                        break
                if target_interface is None:
                    target_interface = next(
                        (obj for obj in interfaces_by_index.values()
                         if obj.type != "virtual"),
                        None,
                    )
                if target_interface is not None:
                    prefix_length = 32
                    try:
                        mask = session.get(
                            f".1.3.6.1.2.1.4.20.1.3.{ip}"
                        ).value
                        prefix_length = ipaddress.IPv4Network(
                            f"0.0.0.0/{mask}"
                        ).prefixlen
                    except Exception:
                        pass
                    address, _ = IPAddress.objects.update_or_create(
                        address=f"{ip}/{prefix_length}",
                        defaults={
                            "status": "active",
                            "assigned_object": target_interface,
                        },
                    )
                    device.primary_ip4 = address
                    device.save(update_fields=["primary_ip4"])
                    print(
                        f"IP_ASSIGNED address={address.address} "
                        f"interface={target_interface.name} primary=true"
                    )
            except Exception as exc:
                print(f"INTERFACES_WARNING ip={ip} name={name} error={exc}")
        if made:
            created_count += 1
            action = "created"
        else:
            updated_count += 1
            action = "updated"
        print(f"NETBOX_{action.upper()} ip={ip} id={device.pk} name={device.name}")
    except Exception as exc:
        error_count += 1
        print(f"NETBOX_ERROR ip={ip} name={name} error={type(exc).__name__}: {exc}")

print(f"SUMMARY created={created_count} updated={updated_count} errors={error_count}")
