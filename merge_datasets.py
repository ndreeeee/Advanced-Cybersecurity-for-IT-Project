"""
merge_datasets.py
-----------------
Unisce honeypot.csv e bob_inject.csv in un unico file merged.csv
usando lo schema di honeypot.csv come riferimento.

Schema output:
  datetime, host, src, proto, type, spt, dpt, srcstr,
  cc, country, locale, localeabbr, postalcode, latitude, longitude
"""

import pandas as pd
import struct
import socket
import hashlib
from datetime import datetime

# ---------------------------------------------------------------------------
# Pool di geo-dati inventati (usati per le righe di bob_inject che
# non hanno informazioni geografiche reali)
# ---------------------------------------------------------------------------
FAKE_GEO_POOL = [
    ("CN", "China",         "Guangdong Sheng", "44",  "",      23.1291,  113.2644),
    ("RU", "Russia",        "Moskva",          "MOW", "101000", 55.7558,  37.6173),
    ("KR", "South Korea",   "Seoul",           "",    "04524",  37.5665, 126.9780),
    ("DE", "Germany",       "Berlin",          "",    "10115",  52.5200,  13.4050),
    ("BR", "Brazil",        "Sao Paulo",       "SP",  "01310", -23.5505, -46.6333),
    ("IN", "India",         "Maharashtra",     "MH",  "400001", 19.0760,  72.8777),
    ("IR", "Iran",          "Tehran",          "",    "11369",  35.6892,  51.3890),
    ("UA", "Ukraine",       "Kyiv",            "",    "01001",  50.4501,  30.5234),
    ("VN", "Vietnam",       "Ha Noi",          "",    "100000", 21.0278, 105.8342),
    ("NL", "Netherlands",   "Noord-Holland",   "NH",  "1011",   52.3676,   4.9041),
]


def ip_to_int(ip_str: str) -> int:
    """Converte un indirizzo IPv4 in intero a 32 bit (big-endian)."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str.strip()))[0]
    except OSError:
        return 0


def proto_num_to_str(num) -> str:
    """Converte il numero di protocollo nella stringa usata da honeypot.csv."""
    mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "IPv6-ICMP"}
    try:
        return mapping.get(int(num), str(num))
    except (ValueError, TypeError):
        return str(num)


def fmt_datetime(dt_str: str) -> str:
    """
    Converte '2020-06-18 12:00:01' nel formato usato da honeypot.csv:
    'M/D/YY H:MM'  (es. '6/18/20 12:00')
    """
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(dt_str.strip(), fmt)
            # Formato senza zero-padding, compatibile Windows e Linux
            return f"{dt.month}/{dt.day}/{str(dt.year)[2:]} {dt.hour}:{dt.minute:02d}"
        except ValueError:
            continue
    return dt_str  # già nel formato corretto o non parsabile


def pick_geo(ip_str: str) -> tuple:
    """
    Sceglie deterministicamente (via hash dell'IP) un record geo dal pool.
    Restituisce (cc, country, locale, localeabbr, postalcode, lat, lon).
    """
    h = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    return FAKE_GEO_POOL[h % len(FAKE_GEO_POOL)]


# ---------------------------------------------------------------------------
# Lettura dei dataset
# ---------------------------------------------------------------------------
print("Lettura honeypot.csv ...")
honeypot = pd.read_csv(
    "honeypot.csv",
    dtype=str,          # tutto come stringa per non perdere formattazione
    low_memory=False,
)
# Rimuovi colonne trailing vuote (honeypot ha una colonna 'Unnamed' finale)
honeypot.columns = honeypot.columns.str.strip()
honeypot = honeypot.loc[:, ~honeypot.columns.str.startswith('Unnamed')]
print(f"   -> {len(honeypot):,} righe | colonne: {list(honeypot.columns)}")

print("\nLettura bob_inject.csv ...")
bob = pd.read_csv("bob_inject.csv", dtype=str)
bob.columns = bob.columns.str.strip()
print(f"   -> {len(bob):,} righe | colonne: {list(bob.columns)}")

# ---------------------------------------------------------------------------
# Normalizzazione di bob_inject → schema honeypot
# ---------------------------------------------------------------------------
print("\nNormalizzazione bob_inject ...")

normalized_rows = []

for _, row in bob.iterrows():
    src_ip  = row.get("src_ip", "").strip()
    dst_ip  = row.get("dst_ip", "").strip()
    proto_n = row.get("proto", "6").strip()

    # Scegli geo inventato: usa dst_ip come seed per variare tra le righe
    # (src_ip e' sempre 172.20.0.12, privato, non ha geo reale)
    geo_seed = dst_ip if dst_ip else src_ip
    cc, country, locale, localeabbr, postalcode, lat, lon = pick_geo(geo_seed)

    normalized_rows.append({
        "datetime":     fmt_datetime(row.get("datetime", "").strip()),
        "host":         row.get("host", "").strip(),
        "src":          ip_to_int(src_ip),          # IP come intero
        "proto":        proto_num_to_str(proto_n),   # numero → stringa
        "type":         "",                          # non presente in bob
        "spt":          row.get("src_port", "").strip(),
        "dpt":          row.get("dst_port", "").strip(),
        "srcstr":       src_ip,                      # IP come stringa
        "cc":           cc,
        "country":      country,
        "locale":       locale,
        "localeabbr":   localeabbr,
        "postalcode":   postalcode,
        "latitude":     lat,
        "longitude":    lon,
        # Colonna extra: conserviamo dst_ip per contesto (sarà rimossa al merge)
        "_dst_ip":      dst_ip,
    })

bob_norm = pd.DataFrame(normalized_rows)

# Allinea le colonne allo schema di honeypot (senza _dst_ip)
target_cols = list(honeypot.columns)
bob_aligned = bob_norm[[c for c in target_cols if c in bob_norm.columns]]

# Colonne presenti in honeypot ma non in bob → aggiungi vuote
for col in target_cols:
    if col not in bob_aligned.columns:
        bob_aligned = bob_aligned.copy()
        bob_aligned[col] = ""

bob_aligned = bob_aligned[target_cols]

# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------
print("\nMerge in corso ...")
merged = pd.concat([honeypot, bob_aligned], ignore_index=True)

output_file = "merged.csv"
merged.to_csv(output_file, index=False)

print(f"\nMerge completato!")
print(f"   honeypot.csv : {len(honeypot):>8,} righe")
print(f"   bob_inject   : {len(bob_aligned):>8,} righe")
print(f"   TOTALE       : {len(merged):>8,} righe")
print(f"   -> salvato in: {output_file}")

# ---------------------------------------------------------------------------
# Anteprima delle ultime N righe (quelle iniettate)
# ---------------------------------------------------------------------------
print("\nAnteprima ultime righe iniettate:")
print(merged.tail(len(bob)).to_string(index=False))
