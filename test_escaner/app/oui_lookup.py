import csv
import os
from functools import lru_cache


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.strip().upper().replace("-", ":")
    mac = mac.replace(":", "")
    return mac


@lru_cache(maxsize=1)
def _load_oui_map() -> dict:
    here = os.path.dirname(__file__)
    path = os.path.join(here, "data", "oui.csv")
    oui_map: dict[str, str] = {}
    if not os.path.exists(path):
        return oui_map

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignment = (row.get("Assignment") or "").strip().upper()
            org = (row.get("Organization Name") or "").strip()
            if assignment and org:
                oui_map[assignment] = org

    return oui_map


def vendor_from_mac(mac: str) -> str | None:
    mac_norm = _normalize_mac(mac)
    if len(mac_norm) < 6:
        return None
    prefix = mac_norm[:6]
    return _load_oui_map().get(prefix)
