# MStarToKeybox
Extracts MStar/MediaTek Widevine L1 keyboxes and PlayReady passphrases from raw eMMC dumps and firmware images.
Only supports **MStar/MediaTek** SoC platforms (LG webOS, Hisense, Sharp, Philips/TPV, Panasonic, etc).

---

## Requirements

Python 3.8+

Install everything once:

```
pip install -r requirements.txt
```

This pulls in `pycryptodome`, `requests`, and `pywidevine`.

Per-script breakdown:
- **kbxtractor** has no external dependencies
- **kbxdecoder** needs `pycryptodome` for decryption, `requests` for URL key sources, and `pywidevine` for `--extract-wvd`
- **prxtractor** needs `pycryptodome`

---

# kbxtractor

Scans raw eMMC dumps and firmware images for MStar Widevine L1 keyboxes and extracts them as encrypted `.bin` files.

## How?

Searches a binary for `MSTAR_SECURE_STORE_FILE_MAGIC_ID` prefix and extracts 228 bytes from matches and filters them with zero-byte density, maximum zero runs, and tail entropy.

## Usage

Scan a single file:

```
python kbxtractor.py firmware.bin
```

Scan all files in the script's directory:

```
python kbxtractor.py --all
```

Save output to a specific folder:

```
python kbxtractor.py firmware.bin -o ./output
```

## Output

Found keyboxes are saved as:

```
<source>_Keybox.bin
<source>_Keybox_2.bin
```

A hex dump of each hit is printed to the console by default.

## All flags

| Flag | Description |
|---|---|
| `files` | One or more binary files to scan |
| `--all` | Scan all files in the current directory |
| `-o`, `--output-dir` | Directory to save extracted keyboxes |
| `--no-hexview` | Suppress hex dump output |
| `--verbose-filters` | Print the reason for rejections |
| `-q`, `--quiet` | Suppress all output except errors |

---

---

# kbxdecoder

Scans raw eMMC dumps and firmware images for MStar Widevine L1 keyboxes, attempts AES decryption using supplied keys. Can generate `.wvd` files.

## How?

Attempts to decrypt raw keybox blobs with ECB, CBC, CFB, OFB, and CTR AES modes. A successful decryption is recognised by the `INNER_MSTAR` marker. Finds the 128-byte Widevine keybox structure, extracts the Device ID, checks the CRC-32, then saves the keybox.

## Key sourcing

The `--key` flag accepts:

- A **hex string** - Single AES key (32, 48, or 64 hex characters for AES-128/192/256)
- A **file path** - Local `.txt` file containing one key per line, or `KEY,IV` pairs for CBC
- A **URL** - Remote key list

Pass `--key` multiple times to combine. 
URL-sourced keys are cached to `keys.txt`.

## Usage

Scan with keys from a local file:

```
python kbxdecoder.py firmware.bin --key keys.txt
```

Scan with keys from a URL:

```
python kbxdecoder.py firmware.bin --key https://example.com/keys.txt
```

Scan with a single manual key:

```
python kbxdecoder.py firmware.bin --key <KEY>
```

Combine sources:

```
python kbxdecoder.py firmware.bin --key https://example.com/keys.txt --key ./extra.txt --key <KEY>
```

Scan all files in the script's directory:

```
python kbxdecoder.py --all --key keys.txt
```

## Output

Example output for found keyboxes:

```
<source>_keybox_raw.bin                        - Raw encrypted keybox blob
<source>_keybox_<device_id>_l1_decrypted.bin   - Decrypted payload
<source>_keybox_<device_id>_l1_wvkeybox.bin    - 128-byte Widevine keybox
<source>_keybox_<device_id>_l1.wvd             - WVD file
manifest.json                                  - JSON logs results
```

The `<device_id>` comes from the decrypted keybox.

## Tested AES

Each key gets tested against:

- ECB
- CBC with zero IV
- CBC with first 16 bytes of ciphertext as IV

## CBC key pairs

To supply a specific key + IV for CBC, format lines in your key file as:

```
AABBCCDD...,00112233...
```

## WVD generation

WVD generation requires pywidevine:

```
client_id.bin      - Provisioned ClientIdentification
private_key.pem    - Device RSA private key
```

Provision the extracted keybox.
Raw keyboxes contain the Device AES Key and provisioning token. RSA keypair is generated.
Once you have both files, run with `--extract-wvd` to generate the `.wvd`.

## Key cache

Keys are saved as `keys.txt` in the output directory. 
Force a re-download with `--force-update-keys`.

## All flags

| Flag | Description |
|---|---|
| `files` | One or more binary files to scan |
| `--all` | Scan all files in the script's directory |
| `-o`, `--output-dir` | Directory to save all output files and key cache |
| `--key HEX\|FILE\|URL` | AES key source - hex string, local file, or URL |
| `--only-custom` | Only use keys passed via `--key`, skip URL cache |
| `--force-update-keys` | Force re-download of URL key sources even if cache is fresh |
| `--no-decrypt` | Skip decryption, only extract raw keybox blobs |
| `--all-matches` | Save output for every key/mode combination that succeeds |
| `--extract-wvd` | Attempt `.wvd` generation |
| `--no-hexview` | Suppress hex dump output |
| `--verbose-filters` | Print the reason for rejections |
| `-q`, `--quiet` | Suppress all output except errors |

---

---

# prxtractor

Extracts PlayReady passphrases from `libplayready.so` and decrypts the associated `bgroupcert.dat` / `zgpriv.dat` files. Also unwraps `zgpriv_protected.dat` for OEMs that reused the PlayReady Porting Kit default Transient/Intermediate keys.

## How?

Two paths, picked per-file by inspecting the first 8 bytes:

- Files starting with `Salted__` are decrypted with OpenSSL `EVP_BytesToKey` (MD5 KDF, AES-256-CBC) using a passphrase. The passphrase is either auto-detected by scanning the supplied `.so` for null-separated `pszBasePhrase` + `pszAdditionalPhrase` strings, or supplied with `--phrase`.
- Anything else is treated as an RFC 3394 AES-Key-Wrap blob and unwrapped with a KEK derived from the PlayReady Porting Kit hardcoded Transient Key (`8B22...427F`) and Intermediate Key (`9CE9...E136`) via AES-CMAC KDF in counter mode. First 32 bytes of the unwrapped material are written as `zgpriv`.

## Usage

Scan a library and decrypt both `.dat` files:

```
python prxtractor.py libplayready.so.0 bgroupcert.dat zgpriv.dat
```

Unwrap a `zgpriv_protected.dat` (no `.so` needed, no passphrase needed):

```
python prxtractor.py "" zgpriv_protected.dat
```

Override the auto-detected passphrase (useful when the `.so` is stripped):

```
python prxtractor.py libplayready.so.0 bgroupcert.dat zgpriv.dat --phrase AsF16eEncr4pt19mt5813
```

List the known Panasonic passphrase candidates:

```
python prxtractor.py --list-phrases
```

## All flags

| Flag | Description |
|---|---|
| `so_path` | Path to `libplayready.so.0` (or any binary) to scan for passphrases. Optional if you only need to unwrap a `zgpriv_protected.dat`. |
| `dat_files` | One or more `.dat` files. Format is auto-detected per file. |
| `--phrase` | Override the auto-detected passphrase. |
| `--list-phrases` | Print the known passphrase candidates and exit. |