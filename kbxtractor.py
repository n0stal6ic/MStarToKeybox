import os
import re
import sys
import json
import mmap
import hashlib
import logging
import argparse
from typing import List, Iterable, Tuple
from dataclasses import dataclass, field

PREFIX_HEX = "4D 53 54 41 52 5F 53 45 43 55 52 45 5F 53 54 4F 52 45 5F 46 49 4C 45 5F 4D 41 47 49 43 5F 49 44"
POSTFIX_HEX_LIST = ["00 00"]
REQUIRE_POSTFIX_AT_EXTRACT_END = True
PRINT_HEXVIEW = True
EXTRACT_LEN = 228
HEXVIEW_WIDTH = 16
MAX_HITS = 0
MAX_ZERO_FRACTION = 0.25
MAX_ZERO_RUN = 16
TAIL_START = 0x90
MIN_TAIL_NONZERO_RATIO = 0.70
SCRIPT_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
log = logging.getLogger(__name__)

@dataclass
class ScanStats:
    files_scanned: int = 0
    candidates_found: int = 0
    filter_rejected: int = 0
    duplicates_skipped: int = 0
    saved: int = 0

    def report(self):
        log.info("\n─────────────────────────────────────────")
        log.info("  Complete")
        log.info("─────────────────────────────────────────")
        log.info(f"  Files scanned      : {self.files_scanned}")
        log.info(f"  Candidates found   : {self.candidates_found}")
        log.info(f"  Filter rejected    : {self.filter_rejected}")
        log.info(f"  Duplicates skipped : {self.duplicates_skipped}")
        log.info(f"  Keyboxes saved     : {self.saved}")
        log.info("─────────────────────────────────────────")

def clean_hex(s: str) -> bytes:
    s = s.replace("0x", "").replace("0X", "")
    s = "".join(s.split())
    if not s:
        return b""
    if len(s) % 2 != 0:
        raise ValueError("Hex string must have an even number of digits.")
    return bytes.fromhex(s)

def iter_all(mm: mmap.mmap, needle: bytes, start: int = 0) -> Iterable[int]:
    i = start
    while True:
        pos = mm.find(needle, i)
        if pos == -1:
            return
        yield pos
        i = pos + 1

def is_printable_ascii(b: int) -> bool:
    return 32 <= b <= 126

def hexview(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{x:02X}" for x in chunk)
        hex_part_padded = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(x) if is_printable_ascii(x) else "." for x in chunk)
        lines.append(f"{base_offset + i:08X}  {hex_part_padded}  |{ascii_part}|")
    return "\n".join(lines)

def best_postfix_window(postfixes: List[bytes]) -> int:
    return max((len(p) for p in postfixes if p), default=0)

def find_postfix_after_extract(
    mm: mmap.mmap,
    postfixes: List[bytes],
    prefix_pos: int,
    file_size: int,
    window: int
) -> Tuple[int, bytes]:
    start = prefix_pos + EXTRACT_LEN
    if start >= file_size:
        return -1, b""
    end = min(file_size, start + window)
    for pf in postfixes:
        if not pf:
            continue
        if start + len(pf) > file_size:
            continue
        pos = mm.find(pf, start, end)
        if pos != -1:
            return pos, pf
    return -1, b""

def max_zero_run(b: bytes) -> int:
    best = 0
    cur = 0
    for x in b:
        if x == 0:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best

def zero_fraction(b: bytes) -> float:
    if not b:
        return 1.0
    return sum(1 for x in b if x == 0) / len(b)

def nonzero_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if x != 0) / len(b)

def passes_filters(block: bytes, verbose: bool = False) -> bool:
    zf = zero_fraction(block)
    if zf > MAX_ZERO_FRACTION:
        if verbose:
            log.debug(f"  REJECT  zero_fraction={zf:.2%} > threshold {MAX_ZERO_FRACTION:.2%}")
        return False

    zr = max_zero_run(block)
    if zr > MAX_ZERO_RUN:
        if verbose:
            log.debug(f"  REJECT  max_zero_run={zr} > threshold {MAX_ZERO_RUN}")
        return False

    tail = block[TAIL_START:] if TAIL_START < len(block) else b""
    if tail:
        nr = nonzero_ratio(tail)
        if nr < MIN_TAIL_NONZERO_RATIO:
            if verbose:
                log.debug(f"  REJECT  tail_nonzero_ratio={nr:.2%} < threshold {MIN_TAIL_NONZERO_RATIO:.2%}")
            return False

    return True

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

_KEYBOX_OUTPUT_RE = re.compile(r'_Keybox(_\d+)?\.bin$', re.IGNORECASE)

def is_skipped_file(path: str) -> bool:
    base = os.path.basename(path)
    if base == SCRIPT_NAME:
        return True
    if _KEYBOX_OUTPUT_RE.search(base):
        return True
    return False

def out_name_for_file(prefix: str, hit_idx: int, output_dir: str) -> str:
    name = f"{prefix}_Keybox.bin" if hit_idx == 1 else f"{prefix}_Keybox_{hit_idx}.bin"
    return os.path.join(output_dir, name)

def extract_from_file(
    path: str,
    prefix: bytes,
    postfixes: List[bytes],
    output_dir: str,
    stats: ScanStats,
    verbose_filters: bool = False
) -> int:
    if not os.path.isfile(path):
        return 0

    file_size = os.path.getsize(path)
    if file_size <= 0:
        return 0

    stats.files_scanned += 1
    per_file_prefix = safe_prefix_from_filename(path)
    saved = 0
    seen = set()

    window = best_postfix_window(postfixes)

    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for ppos in iter_all(mm, prefix, 0):
                if ppos + EXTRACT_LEN > file_size:
                    continue

                qpos, _ = find_postfix_after_extract(mm, postfixes, ppos, file_size, window)
                if qpos == -1:
                    continue

                if REQUIRE_POSTFIX_AT_EXTRACT_END and qpos != (ppos + EXTRACT_LEN):
                    continue

                stats.candidates_found += 1
                block = mm[ppos:ppos + EXTRACT_LEN]

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

                out_name = out_name_for_file(per_file_prefix, saved, output_dir)
                with open(out_name, "wb") as out:
                    out.write(block)

                log.info(f"[{os.path.basename(path)} | Hit #{saved}] -> {out_name}  prefix@0x{ppos:X}  postfix@0x{qpos:X}")

                if PRINT_HEXVIEW:
                    log.info(hexview(block, base_offset=ppos, width=HEXVIEW_WIDTH))
                    log.info("")

                if MAX_HITS and saved >= MAX_HITS:
                    break
        finally:
            mm.close()

    return saved

def write_manifest(entries: list, output_dir: str):
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(entries, f, indent=2)
    log.info(f"\nManifest written -> {manifest_path}")

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="MStarToKeybox",
        description="Extract MStar/MediaTek Widevine L1 keyboxes from raw eMMC dumps and firmware images."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="One or more binary files to scan."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all files in the current directory."
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        help="Directory to save extracted keyboxes."
    )
    parser.add_argument(
        "--no-hexview",
        action="store_true",
        help="Remove keybox hext dump output."
    )
    parser.add_argument(
        "--verbose-filters",
        action="store_true",
        help="Log candidate rejection reason."
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Stop all outputs."
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
    stats = ScanStats()
    manifest_entries = []

    if args.all:
        total = 0
        for name in sorted(os.listdir(SCRIPT_DIR)):
            path = os.path.join(SCRIPT_DIR, name)
            if not os.path.isfile(path):
                continue
            if is_skipped_file(path):
                continue
            total += extract_from_file(path, prefix, postfixes, args.output_dir, stats, args.verbose_filters)
        stats.report()
        if manifest_entries:
            write_manifest(manifest_entries, args.output_dir)
        return 0 if total else 1

    if args.files:
        total = 0
        for path in args.files:
            if not os.path.isfile(path):
                log.error(f"File not found: {path}")
                continue
            total += extract_from_file(path, prefix, postfixes, args.output_dir, stats, args.verbose_filters)
        stats.report()
        if manifest_entries:
            write_manifest(manifest_entries, args.output_dir)
        return 0 if total else 1

    parser.print_help()
    return 2

if __name__ == "__main__":
    raise SystemExit(main())