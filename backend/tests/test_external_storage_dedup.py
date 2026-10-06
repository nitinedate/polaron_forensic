from app.services.forensic_inventory import _distinct_external_storage_devices


def test_distinct_external_storage_devices_excludes_peripherals_and_dedupes():
    rows = [
        {"bus": "USBSTOR", "device_name": "Apacer Portable HDD", "serial": "ABC123"},
        {"bus": "SetupAPI", "device_name": "Apacer Portable HDD", "serial": "ABC123"},
        {"bus": "USBSTOR", "device_name": "Seagate Expansion SCSI Disk Device", "serial": "SEA9"},
        {"bus": "USB", "device_name": "USB Root Hub (USB 3.0)", "serial": ""},
        {"bus": "USB", "device_name": "Integrated Camera", "serial": "CAM1"},
        {"bus": "PCI", "device_name": "NVMe SKHynix_HFM256GD", "serial": "NVME1"},
    ]
    out = _distinct_external_storage_devices(rows)
    assert len(out) == 2
    names = " ".join(str(x.get("device_name")) for x in out)
    assert "Apacer" in names
    assert "Seagate" in names
    assert "Root Hub" not in names
    assert "NVMe" not in names
