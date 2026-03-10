import os
import re
import sys
import zlib
import json
import mmap
import struct
import hashlib
import logging
import argparse
import tempfile
from datetime import date
from typing import Dict, Iterable, List, Optional, Tuple
from dataclasses import dataclass, field

PREFIX_HEX = "4D 53 54 41 52 5F 53 45 43 55 52 45 5F 53 54 4F 52 45 5F 46 49 4C 45 5F 4D 41 47 49 43 5F 49 44"
POSTFIX_HEX_LIST = ["00 00"]
REQUIRE_POSTFIX_AT_EXTRACT_END = True
EXTRACT_LEN = 228
HEXVIEW_WIDTH = 16
MAX_HITS = 0
MAX_ZERO_FRACTION = 0.25
MAX_ZERO_RUN = 16
TAIL_START = 144
MIN_TAIL_NONZERO_RATIO = 0.7
WV_KEYBOX_LEN = 128
WV_DEVICE_ID_OFF = 0
WV_DEVICE_ID_LEN = 32
WV_DEVICE_KEY_OFF = 32
WV_DEVICE_KEY_LEN = 16
WV_KEY_DATA_OFF = 48
WV_KEY_DATA_LEN = 72
WV_MAGIC_OFF = 120
WV_CRC_OFF = 124
WV_MAGIC = b"kbox"
SCRIPT_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def _has_module(name: str) -> bool:
    import importlib

    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


HAS_CRYPTO = _has_module("Crypto")
HAS_REQUESTS = _has_module("requests")
HAS_PYWIDEVINE = _has_module("pywidevine")


@dataclass
class ScanStats:
    files_scanned: int = 0
    candidates_found: int = 0
    filter_rejected: int = 0
    duplicates_skipped: int = 0
    saved: int = 0
    decrypted: int = 0
    decrypt_failed: int = 0
    wvd_generated: int = 0

    def report(self):
        log.info("\n─────────────────────────────────────────")
        log.info("  Complete")
        log.info("─────────────────────────────────────────")
        log.info(f"  Files scanned      : {self.files_scanned}")
        log.info(f"  Candidates found   : {self.candidates_found}")
        log.info(f"  Filter rejected    : {self.filter_rejected}")
        log.info(f"  Duplicates skipped : {self.duplicates_skipped}")
        log.info(f"  Keyboxes saved     : {self.saved}")
        log.info(f"  Decrypted          : {self.decrypted}")
        log.info(f"  Decrypt failed     : {self.decrypt_failed}")
        if self.wvd_generated:
            log.info(f"  WVD files made     : {self.wvd_generated}")
        log.info("─────────────────────────────────────────")


def clean_hex(s: str) -> bytes:
    s = s.replace("0x", "").replace("0X", "")
    s = "".join(s.split())
    if not s:
        return b""
    if len(s) % 2 != 0:
        raise ValueError("Hex string must have an even number of digits.")
    return bytes.fromhex(s)


def is_printable_ascii(b: int) -> bool:
    return 32 <= b <= 126


def hexview(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join((f"{x:02X}" for x in chunk))
        ascii_part = "".join((chr(x) if is_printable_ascii(x) else "." for x in chunk))
        lines.append(
            f"{base_offset + i:08X}  {hex_part.ljust(width * 3 - 1)}  |{ascii_part}|"
        )
    return "\n".join(lines)


_HEX_KEY_RE = re.compile(
    "(?i)(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{48}|[0-9a-f]{32})(?![0-9a-f])"
)


def _parse_keys_from_text(text: str) -> List[str]:
    keys: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0]
        for m in _HEX_KEY_RE.findall(line):
            try:
                kb = bytes.fromhex(m)
            except ValueError:
                continue
            if len(kb) in (16, 24, 32):
                keys.append(m.upper())
    return keys


def _parse_cbc_keys_from_text(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if "," not in line:
            continue
        parts = line.split(",", 1)
        k = parts[0].strip().replace(" ", "")
        iv = parts[1].strip().replace(" ", "")
        try:
            kb = bytes.fromhex(k)
            ivb = bytes.fromhex(iv)
        except ValueError:
            continue
        if len(kb) in (16, 24, 32) and len(ivb) == 16:
            pairs.append((k.upper(), iv.upper()))
    return pairs


def _download_text(url: str, timeout: int = 20) -> str:
    import requests

    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def _cache_path(output_dir: str) -> str:
    return os.path.join(output_dir, "keys.txt")


def _cache_is_fresh(cache_path: str) -> bool:
    if not os.path.exists(cache_path):
        return False
    try:
        mtime = os.path.getmtime(cache_path)
        return date.fromtimestamp(mtime) == date.today()
    except OSError:
        return False


def _load_cache(cache_path: str) -> List[str]:
    keys: List[str] = []
    if not os.path.exists(cache_path):
        return keys
    with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
        keys = _parse_keys_from_text(f.read())
    return keys


def _save_cache(cache_path: str, keys: List[str], sources: List[str]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(cache_path)) or ".", exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        f.write("# kbxdecoder, cached AES keys\n")
        f.write(f"# Updated: {date.today().isoformat()}\n")
        f.write("# Sources:\n")
        for s in sources:
            f.write(f"#   {s}\n")
        f.write("\n")
        for k in keys:
            f.write(k + "\n")
    log.info(f"  [i] Key cache updated -> {cache_path} ({len(keys)} keys)")


@dataclass
class KeyDatabase:
    ecb: List[str] = field(default_factory=list)
    cbc: List[Tuple[str, str]] = field(default_factory=list)


def build_key_database(
    key_args: List[str], output_dir: str, force_update: bool, only_custom: bool
) -> KeyDatabase:
    db = KeyDatabase()
    url_sources: List[str] = []
    file_sources: List[str] = []
    manual_keys: List[str] = []
    for arg in key_args:
        arg = arg.strip()
        no_spaces = arg.replace(" ", "")
        if re.fullmatch("[0-9A-Fa-f]{32}|[0-9A-Fa-f]{48}|[0-9A-Fa-f]{64}", no_spaces):
            manual_keys.append(no_spaces.upper())
        elif arg.lower().startswith("http://") or arg.lower().startswith("https://"):
            url_sources.append(arg)
        elif os.path.isfile(arg):
            file_sources.append(arg)
        else:
            log.warning(
                f"  [!] --key argument not recognised as hex, URL, or file: {arg!r}"
            )
    seen_ecb = set()
    seen_cbc = set()

    def _add_ecb(k: str):
        if k not in seen_ecb:
            seen_ecb.add(k)
            db.ecb.append(k)

    def _add_cbc(k: str, iv: str):
        pair = (k, iv)
        if pair not in seen_cbc:
            seen_cbc.add(pair)
            db.cbc.append(pair)

    for k in manual_keys:
        _add_ecb(k)
    if only_custom:
        return db
    for fpath in file_sources:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for k in _parse_keys_from_text(text):
                _add_ecb(k)
            for k, iv in _parse_cbc_keys_from_text(text):
                _add_cbc(k, iv)
            log.info(f"  [i] Loaded keys from file: {fpath}")
        except Exception as e:
            log.warning(f"  [!] Could not read key file {fpath}: {e}")
    if not url_sources:
        return db
    if not HAS_REQUESTS:
        log.warning("  [!] 'requests' not installed, cannot download key URLs.")
        log.warning("      Install with: pip install requests")
        return db
    cache_file = _cache_path(output_dir)
    if not force_update and _cache_is_fresh(cache_file):
        log.info(f"  [i] Using cached keys: {cache_file}")
        for k in _load_cache(cache_file):
            _add_ecb(k)
        return db
    downloaded: List[str] = []
    for url in url_sources:
        try:
            text = _download_text(url)
            new_keys = _parse_keys_from_text(text)
            new_cbc = _parse_cbc_keys_from_text(text)
            for k in new_keys:
                if k not in seen_ecb:
                    downloaded.append(k)
                    _add_ecb(k)
            for k, iv in new_cbc:
                _add_cbc(k, iv)
            log.info(
                f"  [i] Downloaded {len(new_keys)} ECB + {len(new_cbc)} CBC keys from {url}"
            )
        except Exception as e:
            log.warning(f"  [!] Failed to download {url}: {e}")
    _save_cache(cache_file, downloaded, url_sources)
    return db


def _pad_to_block(data: bytes) -> bytes:
    from Crypto.Util.Padding import pad

    if len(data) % 16 == 0:
        return data
    return pad(data, 16)


@dataclass
class DecryptResult:
    key_hex: str
    mode_name: str
    iv_used: Optional[bytes]
    plaintext: bytes


def _try_key(blob: bytes, key_hex: str) -> List[DecryptResult]:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return []
    results: List[DecryptResult] = []
    MAGIC = b"INNER_MSTAR"

    def ok(dec: bytes) -> bool:
        return MAGIC in dec

    def add(mode: str, iv: Optional[bytes], dec: bytes):
        results.append(DecryptResult(key_hex, mode, iv, dec))

    try:
        dec = AES.new(key, AES.MODE_ECB).decrypt(_pad_to_block(blob))
        if ok(dec):
            add("ECB", None, dec)
    except Exception:
        pass
    iv_zero = b"\x00" * 16
    iv_prefix = blob[:16] if len(blob) >= 16 else None
    ct_after = blob[16:] if len(blob) > 16 else blob
    ivs = [("IV_ZERO", iv_zero, blob)]
    if iv_prefix is not None:
        ivs.append(("IV_PREFIX16", iv_prefix, ct_after))
    for iv_label, iv, ct in ivs:
        try:
            dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(_pad_to_block(ct))
            if ok(dec):
                add(f"CBC({iv_label})", iv, dec)
        except Exception:
            pass
    for iv_label, iv, ct in ivs:
        try:
            dec = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
            if ok(dec):
                add(f"CFB({iv_label})", iv, dec)
        except Exception:
            pass
    for iv_label, iv, ct in ivs:
        try:
            dec = AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
            if ok(dec):
                add(f"OFB({iv_label})", iv, dec)
        except Exception:
            pass
    try:
        ctr = Counter.new(128, initial_value=0)
        dec = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(blob)
        if ok(dec):
            add("CTR(counter=0)", None, dec)
    except Exception:
        pass
    if len(blob) >= 16:
        try:
            init_val = int.from_bytes(blob[:16], "big")
            ctr = Counter.new(128, initial_value=init_val)
            dec = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(blob[16:])
            if ok(dec):
                add("CTR(counter=prefix16)", blob[:16], dec)
        except Exception:
            pass
    return results


def _try_cbc_pair(blob: bytes, key_hex: str, iv_hex: str) -> List[DecryptResult]:
    from Crypto.Cipher import AES

    MAGIC = b"INNER_MSTAR"
    try:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(_pad_to_block(blob))
        if MAGIC in dec:
            return [
                DecryptResult(key_hex, f"CBC(explicit_iv={iv_hex[:8]}...)", iv, dec)
            ]
    except Exception:
        pass
    return []


def decrypt_blob(
    blob: bytes, db: KeyDatabase, stop_on_first: bool = True
) -> List[DecryptResult]:
    if not HAS_CRYPTO:
        return []
    all_results: List[DecryptResult] = []
    for key_hex in db.ecb:
        res = _try_key(blob, key_hex)
        all_results.extend(res)
        if stop_on_first and all_results:
            return all_results
    for key_hex, iv_hex in db.cbc:
        res = _try_cbc_pair(blob, key_hex, iv_hex)
        all_results.extend(res)
        if stop_on_first and all_results:
            return all_results
    return all_results


def extract_payload(dec: bytes) -> bytes:
    for offset in (64, 96):
        candidate = dec[offset:]
        if b"CHAI" in candidate:
            return candidate
        if b"kbox" in candidate:
            idx = candidate.find(b"kbox")
            start = max(0, idx - WV_MAGIC_OFF)
            return candidate[start : start + WV_KEYBOX_LEN]
    return dec[64:]


@dataclass
class WVKeybox:
    device_id: bytes
    device_key: bytes
    key_data: bytes
    crc_valid: bool
    raw: bytes


def _crc32_widevine(data: bytes) -> int:
    return zlib.crc32(data[:WV_CRC_OFF]) & 4294967295


def parse_wv_keybox(payload: bytes) -> Optional[WVKeybox]:
    idx = payload.find(WV_MAGIC)
    if idx == -1:
        return None
    start = idx - WV_MAGIC_OFF
    if start < 0 or start + WV_KEYBOX_LEN > len(payload):
        return None
    raw = payload[start : start + WV_KEYBOX_LEN]
    device_id = raw[WV_DEVICE_ID_OFF : WV_DEVICE_ID_OFF + WV_DEVICE_ID_LEN]
    device_key = raw[WV_DEVICE_KEY_OFF : WV_DEVICE_KEY_OFF + WV_DEVICE_KEY_LEN]
    key_data = raw[WV_KEY_DATA_OFF : WV_KEY_DATA_OFF + WV_KEY_DATA_LEN]
    stored_crc = struct.unpack_from("<I", raw, WV_CRC_OFF)[0]
    computed_crc = _crc32_widevine(raw)
    crc_valid = stored_crc == computed_crc
    return WVKeybox(
        device_id=device_id,
        device_key=device_key,
        key_data=key_data,
        crc_valid=crc_valid,
        raw=raw,
    )


def device_id_slug(wvkb: WVKeybox) -> str:
    raw_id = wvkb.device_id.rstrip(b"\x00")
    try:
        s = raw_id.decode("ascii")
        s = re.sub("[^A-Za-z0-9_.-]", "_", s).strip("_")
        if s:
            return s[:24]
    except Exception:
        pass
    return wvkb.device_id[:8].hex().upper()


def _make_wvd(private_key_pem: bytes, client_id_blob: bytes, out_path: str) -> bool:
    if not HAS_PYWIDEVINE:
        return False
    try:
        from pywidevine.device import Device, DeviceTypes
        from pywidevine.license_protocol_pb2 import ClientIdentification
        from Crypto.PublicKey import RSA

        client_id = ClientIdentification()
        client_id.ParseFromString(client_id_blob)
        rsa_key = RSA.import_key(private_key_pem)
        device = Device(
            type_=DeviceTypes.ANDROID,
            security_level=1,
            flags=None,
            private_key=rsa_key,
            client_id=client_id,
        )
        device.dump(out_path)
        return os.path.exists(out_path)
    except Exception as e:
        log.debug(f"  WVD generation error: {e}")
        return False


def safe_prefix_from_filename(path: str) -> str:
    base = os.path.basename(path)
    root, _ = os.path.splitext(base)
    safe = []
    for ch in root:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    s = "".join(safe).strip("._-")
    return s or "file"


_SKIP_RE = re.compile(
    "(_raw|_decrypted|_payload|_l1)(\\.(bin|wvd|prd))?$", re.IGNORECASE
)


def is_skipped_file(path: str) -> bool:
    base = os.path.basename(path)
    if base == SCRIPT_NAME:
        return True
    if _SKIP_RE.search(os.path.splitext(base)[0]):
        return True
    if base == "keys.txt":
        return True
    return False


def build_stem(
    source_prefix: str,
    hit_idx: int,
    device_id_str: Optional[str],
    key_desc_slug: Optional[str],
    confirmed_l1: bool,
) -> str:
    parts = [source_prefix, str(hit_idx)]
    if device_id_str:
        parts.append(device_id_str)
    elif key_desc_slug:
        slug = re.sub("[^A-Za-z0-9_.-]", "_", key_desc_slug)[:32].strip("_")
        if slug:
            parts.append(slug)
    if confirmed_l1:
        parts.append("l1")
    return "_".join(parts)


PRINT_HEXVIEW = True


def iter_all(mm: mmap.mmap, needle: bytes, start: int = 0) -> Iterable[int]:
    i = start
    while True:
        pos = mm.find(needle, i)
        if pos == -1:
            return
        yield pos
        i = pos + 1


def best_postfix_window(postfixes: List[bytes]) -> int:
    return max((len(p) for p in postfixes if p), default=0)


def find_postfix_after_extract(
    mm: mmap.mmap, postfixes: List[bytes], prefix_pos: int, file_size: int, window: int
) -> Tuple[int, bytes]:
    start = prefix_pos + EXTRACT_LEN
    if start >= file_size:
        return (-1, b"")
    end = min(file_size, start + window)
    for pf in postfixes:
        if not pf or start + len(pf) > file_size:
            continue
        pos = mm.find(pf, start, end)
        if pos != -1:
            return (pos, pf)
    return (-1, b"")


def max_zero_run(b: bytes) -> int:
    best = cur = 0
    for x in b:
        cur = cur + 1 if x == 0 else 0
        best = max(best, cur)
    return best


def zero_fraction(b: bytes) -> float:
    return sum((1 for x in b if x == 0)) / len(b) if b else 1.0


def nonzero_ratio(b: bytes) -> float:
    return sum((1 for x in b if x != 0)) / len(b) if b else 0.0


def passes_filters(block: bytes, verbose: bool = False) -> bool:
    zf = zero_fraction(block)
    if zf > MAX_ZERO_FRACTION:
        if verbose:
            log.debug(f"  REJECT  zero_fraction={zf:.2%} > {MAX_ZERO_FRACTION:.2%}")
        return False
    zr = max_zero_run(block)
    if zr > MAX_ZERO_RUN:
        if verbose:
            log.debug(f"  REJECT  max_zero_run={zr} > {MAX_ZERO_RUN}")
        return False
    tail = block[TAIL_START:] if TAIL_START < len(block) else b""
    if tail:
        nr = nonzero_ratio(tail)
        if nr < MIN_TAIL_NONZERO_RATIO:
            if verbose:
                log.debug(
                    f"  REJECT  tail_nonzero_ratio={nr:.2%} < {MIN_TAIL_NONZERO_RATIO:.2%}"
                )
            return False
    return True


def extract_from_file(
    path: str,
    prefix: bytes,
    postfixes: List[bytes],
    output_dir: str,
    stats: ScanStats,
    manifest_entries: list,
    db: KeyDatabase,
    verbose_filters: bool = False,
    no_decrypt: bool = False,
    stop_on_first_key: bool = True,
    extract_wvd: bool = False,
) -> int:
    if not os.path.isfile(path):
        return 0
    file_size = os.path.getsize(path)
    if file_size <= 0:
        return 0
    stats.files_scanned += 1
    src_prefix = safe_prefix_from_filename(path)
    saved = 0
    seen = set()
    window = best_postfix_window(postfixes)
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for ppos in iter_all(mm, prefix, 0):
                if ppos + EXTRACT_LEN > file_size:
                    continue
                qpos, _ = find_postfix_after_extract(
                    mm, postfixes, ppos, file_size, window
                )
                if qpos == -1:
                    continue
                if REQUIRE_POSTFIX_AT_EXTRACT_END and qpos != ppos + EXTRACT_LEN:
                    continue
                stats.candidates_found += 1
                block = bytes(mm[ppos : ppos + EXTRACT_LEN])
                if not passes_filters(block, verbose=verbose_filters):
                    stats.filter_rejected += 1
                    continue
                h = hashlib.sha256(block).digest()
                if h in seen:
                    stats.duplicates_skipped += 1
                    continue
                seen.add(h)
                saved += 1
                stats.saved += 1
                raw_stem = f"{src_prefix}_{saved}_raw"
                raw_path = os.path.join(output_dir, raw_stem + ".bin")
                with open(raw_path, "wb") as out:
                    out.write(block)
                log.info(f"[{os.path.basename(path)} | Hit #{saved}]")
                log.info(f"  Raw keybox   -> {raw_path}")
                log.info(f"  Offset       : 0x{ppos:X}  (postfix @ 0x{qpos:X})")
                if PRINT_HEXVIEW:
                    log.info(hexview(block, base_offset=ppos, width=HEXVIEW_WIDTH))
                    log.info("")
                entry: Dict = {
                    "source_file": path,
                    "offset_hex": hex(ppos),
                    "sha256": hashlib.sha256(block).hexdigest(),
                    "raw_file": raw_path,
                    "decrypted": False,
                    "decrypt_key": None,
                    "decrypt_mode": None,
                    "payload_file": None,
                    "wvkb_device_id": None,
                    "wvkb_crc_valid": None,
                    "wvd_file": None,
                }
                if not no_decrypt:
                    if not HAS_CRYPTO:
                        log.warning(
                            "  [!] pycryptodome not installed, skipping decryption."
                        )
                        log.warning("      Install with: pip install pycryptodome")
                    elif not (db.ecb or db.cbc):
                        log.warning(
                            "  [!] No keys provided, use --key to supply keys."
                        )
                    else:
                        ecb_count = len(db.ecb)
                        cbc_count = len(db.cbc)
                        log.info(
                            f"  [~] Trying {ecb_count} ECB + {cbc_count} CBC key(s) across 5 AES modes..."
                        )
                        results = decrypt_blob(
                            block, db, stop_on_first=stop_on_first_key
                        )
                        if not results:
                            stats.decrypt_failed += 1
                            log.info("  [-] No matching decryption key found.")
                            log.info("      Supply keys with --key <hex|file|url>")
                        else:
                            for r_idx, r in enumerate(results):
                                stats.decrypted += 1
                                payload = extract_payload(r.plaintext)
                                wvkb = parse_wv_keybox(payload)
                                dev_id_str = device_id_slug(wvkb) if wvkb else None
                                key_slug = re.sub("\\s+", "_", r.mode_name)[:20]
                                final_stem = build_stem(
                                    source_prefix=src_prefix,
                                    hit_idx=saved,
                                    device_id_str=dev_id_str,
                                    key_desc_slug=key_slug,
                                    confirmed_l1=True,
                                )
                                if len(results) > 1:
                                    final_stem += f"_match{r_idx + 1}"
                                dec_path = os.path.join(
                                    output_dir, final_stem + "_decrypted.bin"
                                )
                                with open(dec_path, "wb") as pf:
                                    pf.write(payload)
                                iv_info = (
                                    f", iv={r.iv_used.hex().upper()}"
                                    if r.iv_used
                                    else ""
                                )
                                log.info(f"  [+] Decrypted    -> {dec_path}")
                                log.info(f"  [+] Key          : {r.key_hex}")
                                log.info(f"  [+] Mode         : {r.mode_name}{iv_info}")
                                entry["decrypted"] = True
                                entry["decrypt_key"] = r.key_hex
                                entry["decrypt_mode"] = r.mode_name
                                entry["payload_file"] = dec_path
                                if wvkb:
                                    crc_status = "OK" if wvkb.crc_valid else "MISMATCH"
                                    log.info(
                                        f"  [+] Device ID    : {dev_id_str}  (CRC: {crc_status})"
                                    )
                                    entry["wvkb_device_id"] = dev_id_str
                                    entry["wvkb_crc_valid"] = wvkb.crc_valid
                                    wvkb_path = os.path.join(
                                        output_dir, final_stem + "_wvkeybox.bin"
                                    )
                                    with open(wvkb_path, "wb") as wf:
                                        wf.write(wvkb.raw)
                                    log.info(f"  [+] WV Keybox    -> {wvkb_path}")
                                if extract_wvd:
                                    if not HAS_PYWIDEVINE:
                                        log.info(
                                            "  [i] pywidevine not installed, cannot generate WVD."
                                        )
                                        log.info(
                                            "      Install with: pip install pywidevine"
                                        )
                                    else:
                                        client_id_path = os.path.join(
                                            SCRIPT_DIR, "client_id.bin"
                                        )
                                        priv_key_path = os.path.join(
                                            SCRIPT_DIR, "private_key.pem"
                                        )
                                        if os.path.exists(
                                            client_id_path
                                        ) and os.path.exists(priv_key_path):
                                            wvd_path = os.path.join(
                                                output_dir, final_stem + ".wvd"
                                            )
                                            with open(client_id_path, "rb") as ci:
                                                client_id_blob = ci.read()
                                            with open(priv_key_path, "rb") as pk:
                                                private_key_pem = pk.read()
                                            if _make_wvd(
                                                private_key_pem,
                                                client_id_blob,
                                                wvd_path,
                                            ):
                                                stats.wvd_generated += 1
                                                entry["wvd_file"] = wvd_path
                                                log.info(
                                                    f"  [+] WVD          -> {wvd_path}"
                                                )
                                            else:
                                                log.info("  [!] WVD generation failed.")
                                        else:
                                            log.info(
                                                "  [i] WVD generation requires provisioned client_id.bin"
                                            )
                                            log.info(
                                                "      + private_key.pem in the same directory as this script."
                                            )
                                            log.info(
                                                "      The raw keybox has been saved, use it to provision"
                                            )
                                            log.info(
                                                "      the device and obtain these files first."
                                            )
                manifest_entries.append(entry)
                log.info("")
                if MAX_HITS and saved >= MAX_HITS:
                    break
        finally:
            mm.close()
    return saved


def write_manifest(entries: list, output_dir: str):
    path = os.path.join(output_dir, "manifest.json")
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    log.info(f"Manifest written -> {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="kbxdecoder",
        description="Extract and decode MStar/MediaTek Widevine keyboxes from eMMC dumps and firmware images. Decryption from ECB, CBC, CFB, OFB, and CTR modes using supplied keys (hex string, local file, or URL).",
    )
    parser.add_argument("files", nargs="*", help="One or more binary files to scan.")
    parser.add_argument(
        "--all", action="store_true", help="Scan all files in the script's directory."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=SCRIPT_DIR,
        help="Directory to save all output files and key cache. (default: script directory)",
    )
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="HEX|FILE|URL",
        help="AES key source. Accepts any of: a 32/48/64-char hex string, a path to a local key file, or a URL to download a key list from. Repeat to combine multiple sources. Lines formatted as KEY,IV are treated as CBC pairs.",
    )
    parser.add_argument(
        "--only-custom",
        action="store_true",
        help="Only use keys supplied via --key. Skip URL downloads and cache.",
    )
    parser.add_argument(
        "--force-update-keys",
        action="store_true",
        help="Force re-download of URL key sources even if cache is fresh.",
    )
    parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Skip decryption entirely. Only extract raw keybox blobs.",
    )
    parser.add_argument(
        "--all-matches",
        action="store_true",
        help="Save output for every key/mode match, not just the first.",
    )
    parser.add_argument(
        "--extract-wvd",
        action="store_true",
        help="Attempt .wvd file generation. Requires pywidevine and provisioned client_id.bin + private_key.pem in the script directory.",
    )
    parser.add_argument(
        "--no-hexview", action="store_true", help="Suppress hex dump output."
    )
    parser.add_argument(
        "--verbose-filters",
        action="store_true",
        help="Log the reason each candidate block is rejected.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress all output except errors."
    )
    args = parser.parse_args()
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose_filters:
        logging.getLogger().setLevel(logging.DEBUG)
    global PRINT_HEXVIEW
    if args.no_hexview:
        PRINT_HEXVIEW = False
    try:
        prefix = clean_hex(PREFIX_HEX)
        postfixes = [clean_hex(x) for x in POSTFIX_HEX_LIST]
    except (ValueError, Exception) as e:
        log.error(f"Failed to parse hex constants: {e}")
        return 2
    postfixes = [p for p in postfixes if p]
    if not prefix or not postfixes or EXTRACT_LEN <= 0:
        log.error("Error: prefix, postfix, or EXTRACT_LEN is missing.")
        return 2
    os.makedirs(args.output_dir, exist_ok=True)
    if not args.quiet and (not args.no_decrypt):
        if not HAS_CRYPTO:
            log.info("[!] pycryptodome not found, decryption disabled.")
            log.info("    Install with: pip install pycryptodome")
        if args.extract_wvd and (not HAS_PYWIDEVINE):
            log.info("[i] pywidevine not found, WVD generation disabled.")
            log.info("    Install with: pip install pywidevine")
        log.info("")
    db = KeyDatabase()
    if not args.no_decrypt and args.key:
        log.info("[*] Resolving key sources...")
        db = build_key_database(
            key_args=args.key,
            output_dir=args.output_dir,
            force_update=args.force_update_keys,
            only_custom=args.only_custom,
        )
        log.info(f"    ECB candidates : {len(db.ecb)}")
        log.info(f"    CBC pairs      : {len(db.cbc)}")
        log.info("")
    elif not args.no_decrypt and (not args.key):
        log.info("[!] No keys supplied. Use --key <hex|file|url> to enable decryption.")
        log.info("")
    stats = ScanStats()
    manifest_entries = []
    scan_kwargs = dict(
        output_dir=args.output_dir,
        stats=stats,
        manifest_entries=manifest_entries,
        db=db,
        verbose_filters=args.verbose_filters,
        no_decrypt=args.no_decrypt,
        stop_on_first_key=not args.all_matches,
        extract_wvd=args.extract_wvd,
    )
    if args.all:
        total = 0
        for name in sorted(os.listdir(SCRIPT_DIR)):
            fpath = os.path.join(SCRIPT_DIR, name)
            if not os.path.isfile(fpath) or is_skipped_file(fpath):
                continue
            total += extract_from_file(fpath, prefix, postfixes, **scan_kwargs)
        stats.report()
        if manifest_entries:
            write_manifest(manifest_entries, args.output_dir)
        return 0 if total else 1
    if args.files:
        total = 0
        for fpath in args.files:
            if not os.path.isfile(fpath):
                log.error(f"File not found: {fpath}")
                continue
            total += extract_from_file(fpath, prefix, postfixes, **scan_kwargs)
        stats.report()
        if manifest_entries:
            write_manifest(manifest_entries, args.output_dir)
        return 0 if total else 1
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
