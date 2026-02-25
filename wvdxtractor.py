import os
import re
import sys
import json
import mmap
import hashlib
import logging
import argparse
import struct
import subprocess
import tempfile
from typing import List, Iterable, Tuple, Optional, Dict
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

AES_ECB_KEYS: List[Tuple[str, str]] = [
    ("214BF3C129547AF31D32A5ECB4742192", "unknown"),
    ("B9C956919B48E1671564F4CADB5FE63C", "unknown"),
    ("224420CC1EBCA39100010001846276CC", "unknown"),
    ("088085E0077085E08990A0E18AA0A0E1", "unknown"),
    ("0C6E750369A106355D7290F482205D61", "unknown"),
    ("0BB085E004608DE58880A0E1B95093E1", "unknown"),
    ("1100E63045E019B5A8A1CB49EA9625B4", "unknown"),
    ("F72F0FE303CC80E1BC3406E3B11095E1", "unknown"),
    ("203040E30100A0E3B010CCE100C094E5", "unknown"),
    ("13541C00B0801C00A01820006D801C00", "unknown"),
    ("0007FF4154534D92FC55AA0FFF0110E0", "default"),
    ("BC1197CA30AA0FC84F7FE62E09FD3D9F", "Hisense"),
    ("8981D083B3D53B3DF1AC529A70F244C0", "Vestel"),
    ("24490B4CC95F739CE34138478E47139E", "Vestel"),
    ("1234123412341234", "mb97 to mb130"),
    ("3503B1CDE3401EC06030C12A4311F4A5", "KTC"),
    ("E33AB4C45C2570B8AD15A921F752DEB6", "LG"),
    ("1F1E1D1C1B1A19180706050403020100", "BCM35230/early MTK5369 and LG1152 (common)"),
    ("7184C9C428D03C445188234D5A827196", "mtk5369 - Mediatek GP4 - HE_DTV_GP4I_AFAAATAA"),
    ("385A992430196A8C44F1985823C01440", "mtk5398 (a2) - Mediatek NetCast 4/4.5 - HE_LCD_NC5M_AAAAAIAA"),
    ("8E32E4608871ECE9B6301999D5155A07", "mtka5lr (mt5882) - Mediatek webOS 2 (2015) - HE_DTV_W15L_AFAAABAA"),
    ("6856A0482475A8B41728A35474810203", "new BCM35230"),
    ("2F2E2D2C2B2A29281716151413121110", "Saturn7/BCM3556"),
    ("212D3B2A5C2D3A2C4D5B234B1A321D2A", "new Saturn7/old LM1"),
    ("4F836AAEB4301F26172A9B0E1120EAF4", "LM1 PDP"),
    ("4EE662C7A2C0917F7328DE73A0836C6B", "LM1 LCD"),
    ("2F534ABE34801A36B7DA6B3EB1C04AD4", "m1 - MStar non-webOS - LN45*, LN53*, LN54*, LN565*, LA61*, LA643*, MA53*, PN45*, PN65*"),
    ("7B2CA5943D2E752CF58606228C5B2DAD", "m1a - MStar non-webOS (L15 signage) - BS_LCD_LE15_AAAAAIAM"),
    ("D55C6864035A8C8A2B35A6D6C4565596", "m2 - MStar SimpleSmart - HE_LCD_SS1A_AFAAAIAA"),
    ("ADB92D9E23035522F4708CC259B31EA2", "m2 - MStar webOS 3.0 (2016) - HE_DTV_W16R_AFAAABAA"),
    ("D2E6EE17639DFE2F81D3840FA0BC334A", "m2r - MStar webOS 3.5 (2017) - HE_DTV_W17R_AFAAABAA"),
    ("4F6DE80C0362FD562464BC2073D15567", "m3 - MStar webOS 4.0 (2018) - HE_DTV_W18R_AFAAABAA"),
    ("88723D91920712D0BAFE87A25E6E8EC7", "m3r - MStar webOS 4.5 (2019) - HE_DTV_W19R_AFAAATAA"),
    ("68A284B4953CAD15024BED2C4F852A09", "lm14 - MStar NetCast 4.5 (2014/2015) - HE_LCD_NC5U_AAADABAA"),
    ("19F51EE9B949C89E41AE136F48BB405C", "lm14a - MStar webOS 2 (2015) - HE_DTV_W15A_AFADABAA"),
    ("F8F6BD1AA24506C2759E1BE1D51BB43C", "lm14alite - MStar webOS 2 (2015) - HE_DTV_W15B_AFADABAA"),
    ("96F464CB29CDFF5441FD87D47D084FF8", "lm15u - MStar webOS 2 (2015) - HE_DTV_W15U_AFADABAA"),
    ("6FCCC4AA3389B614BABE462498D2020A", "lm18a - MStar webOS 4.0 (2018) - HE_DTV_W18A_AFADATAA"),
    ("806B982279521809DBAD9E2E6BF377763903565A7EB4604BAB1E1503DBFC4326", "lm21a - MStar webOS 6 (2021) - HE_DTV_W21A_AFADATAA"),
    ("B65119E0E6CB5DB19C69B4CC78FAC3A87C747E5AEFDE8FF58F2CD47128D9E16D", "lm21u (mt5889) - MStar webOS 6 (2021) - HE_DTV_W21U_AFADATAA"),
    ("FC9D81DEC206BA62614C949C43D2DA91D23E9FF3DF9674D69A444D13277BDF96", "lm21ut - MStar webOS 6 StanbyME (2022) - HE_DTV_N21D_AFAAATAA"),
    ("3435663331313732316538383063663538306161643131653335323334613034", "lm21an - MStar webOS 7 (2022) - HE_DTV_W22A_AFADATAA"),
    ("1FB2C3B789D5EA48ED16E79A0343986C691DACEC872BB07787D0F722AF5D1E2C", "lm21ann - MStar webOS 8 (2023) - HE_DTV_W23A_AFADATAA"),
    ("4813B5B63C998A2874EF3320684AC8D9", "lg1152 - LX GP4 - HE_DTV_GP4H_AFAAATAA"),
    ("14B3623488212250C7C992AACD537447", "lg115x - LX NC4 - HE_LCD_NC4H_AAADABAA"),
    ("12C344FDD2871C983CD0FBBC25143974", "lg1154 (h13, goldfinger) - LX webOS 1 (2014) - HE_DTV_WT1H_AFAAABAA"),
    ("34CC219D3AFC102433109BBC1DA44095", "m14 (m14tv) - LX webOS 1 (2014) - HE_DTV_WT1M_AFAAATAA"),
    ("5A167D8C342EF094800E7CFA2D10F2D0", "m14 (m14tv) - LX webOS 2 (2015) - HE_DTV_W15M_AFAAATAA"),
    ("13F56BE4B4A0829598DB8F74065A263B", "h15 - LX webOS 2 (2015) - HE_DTV_W15H_AFADATAA"),
    ("3679EF1840B7FDEBC1FBF95A0CAFCE3E", "m16 - LX webOS 3.0 (2016) - HE_DTV_W16M_AFADABAA"),
    ("5804DF78CB8DC6A71C05DAB0F1EDE3E1", "m16lite - LX webOS 3.0 (2016) - HE_DTV_W16N_AFADABAA"),
    ("1B3C76ADD3F5EE6B089DB253747A8CD4", "m16p - LX webOS 3.5 (2017) - HE_DTV_W17H_AFADABAA"),
    ("3C9D30DF3A95C1AA41928813292BD947", "m16plite - LX webOS 3.5 (2017) - HE_DTV_W17M_AFADATAA"),
    ("89E11D498392F5A521145738EF036AE5", "m16pstb - LX webOS 3.5 (2017) - HE_DTV_W17S_AFADATAA"),
    ("437C02F0DF99F2072D1A64EEBBD2953B", "m16pp - LX webOS 4.0 (2018) - HE_DTV_W18H_AFADABAA"),
    ("3471D9BFC5F4B34A8997D56932F34D94", "m16pplite - LX webOS 4.0 (2018) - HE_DTV_W18M_AFADATAA"),
    ("3FE1CBE11BD658BB37813E05052D5FE5", "m16p3 - LX webOS 4.5 (2019) - HE_DTV_W19H_AFADABAA"),
    ("A2FA48FCC1A22FD2F1944BEFA8403765EF178D4F4AB0E81AC7B5B267ACBDF14D", "m23 - LX webOS 8 (2023) - HE_DTV_W23M_AFADATAA"),
    ("E529BCDEDF8E49667C0FA3A81174B65E", "o18 - LX webOS 4.0 (2018) - HE_DTV_W18O_AFABABAA"),
    ("4ACD2CA8425BBA6C49FD03A174300239", "o18 - LX webOS 4.5 (2019) - HE_DTV_W19O_AFABABAA"),
    ("C9EF645424A625BBAE7521394564025EC6252658FB650D33633111BD40C76011", "o20 - LX webOS 5 (2020) - HE_DTV_W20O_AFABATAA"),
    ("944288798A122C6130B661BEE52DF4FE42120F60A61E312DCFC1411E300A29AE", "o20n - LX webOS 6 (2021) - HE_DTV_W21O_AFABATAA"),
    ("3861333237633238613136633438663239623238623037656335623433353862", "o22 - LX webOS 7 (2022) - HE_DTV_W22O_AFABATAA"),
    ("CF5D6DC934F18618B968382368E17BA971DEAA2ECDFC906874B327D87076E228", "o22n - LX webOS 8 (2023) - HE_DTV_W23O_AFABATAA"),
    ("53D6DC79418C1A2371DC9F926CD3A3A06F4E7E4396464B5F41248083C2C65637", "o22n2 - LX webOS 9 (2024) - HE_DTV_W24G_AFABATAA"),
    ("B7724DBBF2AEA073131E8E7D62D114E2AA02F99D17CD7350C14466624528ED79", "o24 - LX webOS 9 (2024) - HE_DTV_W24O_AFABATAA"),
    ("FE90B0C1BE8CC28A9738333F95AC2C58777BDE7D4E8CABABA73B24FB7D1781C7", "o22n3 - LX webOS 10 (2025) - HE_DTV_W25G_AFABATAA"),
    ("52A208FA24E7E70730A40999B1C22C148F4920484BC50B515D243E35D14689F1", "o24n - LX webOS 10 (2025) - HE_DTV_W25O_AFABATAA"),
    ("CD4171FC9C06869627A67EA7B66D739D", "o18k - LX webOS 4.5 (2019) - HE_DTV_W19K_AFADATAA"),
    ("0EE52A12A2EB5DE2E13999187B14913F6D3367A79B39AC35979A51E5C12A4FDF", "o208k - LX webOS 5 (2020) - HE_DTV_W20K_AFADATAA"),
    ("E27E6AFE44B7866D60C24ED27904ECB296CA69B4251478B5248C03851F08ECF5", "e60n - LX webOS 6 (2021) - HE_DTV_W21K_AFADATAA"),
    ("F2B78AEBAD6D86A17B4742B2B84B60F4", "k2l - Realtek webOS 3.0 (2016) - HE_DTV_W16K_AFADATAA"),
    ("C2FBBC5DDD9D366B7FD6CAEB90F86039", "k2lp - Realtek webOS 3.0 (2016) - HE_DTV_W16P_AFADABAA"),
    ("1C966DFA0E5AE9946AAF8D2EC06B9E18", "k3lp - Realtek webOS 3.5 (2017) - HE_DTV_W17P_AFADABAA"),
    ("AD17A5923B525FD21DB765A5B6822FBD", "k5lp - Realtek webOS 4.5 (2019) - HE_DTV_W19P_AFADABAA"),
    ("388BE4B04BD98E7C3CA45A4C6CA346DD2EB32BDCD05DC28FC4A87C9625294A5E", "k6lp - Realtek webOS 5 (2020) - HE_DTV_W20P_AFADATAA"),
    ("377050F9B9D91CD803ACAACCEA4046DD99B01CFBB0010451F4F87A1620C4BAEF", "k6lpfhd - Realtek webOS 5 (2020) - HE_DTV_W20L_AFAAJAAA"),
    ("395324AD369A529EABAC71FE1E72C25CE25594294D47303BCB2629241AFA4C98", "k6hp - Realtek webOS 5 (2020) - HE_DTV_W20H_AFADABAA"),
    ("74514676D68B9A72A0093CEF56D3067484E1F4D5CF7D4B4ED389BED030FA1B09", "k7lp - Realtek webOS 6 (2021) - HE_DTV_W21P_AFADATAA"),
    ("6A42D2485B716B25AE5C9921176588D167C25B902D4EF2903AF5C1FCC61D34C9", "k8lp - Realtek webOS 7 (2022) - HE_DTV_W22P_AFADATAA"),
    ("A35A57DFDD8266F7CE1AF991EC67BABF6723653ABB9A7D48A4B8AB2A2485BCFE", "k8hp - Realtek webOS 7 (2022) - HE_DTV_W22H_AFADATAA"),
    ("703373367638792F423F4528482B4D6251655468576D5A7134743777217A2443", "k8lp - Realtek webOS 7 hospitality (2022) - HE_IDD_H22P_AHAAATAA"),
    ("6251655468576D5A7133743677397A24432646294A404E635266556A586E3272", "k8hp - Realtek webOS 7 hospitality (2022) - HE_IDD_H22H_AHAAATAA"),
    ("3764336361633437326166373639383663353863363039316332383031626637", "k8ap - Realtek webOS 7 (2022) - HE_DTV_W22L_AFAAATAA"),
    ("DFFD1E4F093E305451D4F3752E63BA9A3E6A6404922D986DF36C00818F5595C1", "k8hpp - Realtek webOS 8 (2023) - HE_DTV_W23H_AFADATAA"),
    ("EC2C89B4AF45B5EB7EA9A83DD2387810C0815BD31BBFE1D17C809E7D68339112", "k8lpn - Realtek webOS 8 (2023) - HE_DTV_W23P_AFADATAA"),
    ("F322A9CA1D523C358DD2FD97D5660E25386C9C60E423632AEC9723D282BE971D", "kf23f - Realtek webOS 8 smart monitors (2023) - HE_MNT_S23Y_AAAAGLAA"),
    ("6252A0816884997B2FCA30662561A721A4BCC40B18CBEA5D363FA844F17D7DE9", "kid23q - Realtek webOS 8 ultrawide monitors (2023) - HE_MNT_S23Z_AAACGLAA"),
    ("7638792F423F4528482B4D6251655368566D597133743677397A24432646294A", "k8lpn - Realtek webOS 8 hospitality (2023) - HE_IDD_H23P_AHAAATAA"),
    ("6B5AD1BE81D7A1A494F58EB659431850C1B681826EE4428394D4897052691756", "k8lpn2 - Realtek webOS 9 (2024) - HE_DTV_W24P_AFADATAA"),
    ("FA9EBB838B7BAFBA75EFE8D5A3560374EB0699A113411CA924051B4ADB52E10D", "k24 - Realtek webOS 9 (2024) - HE_DTV_W24H_AFADATAA"),
    ("1A8ADAB21D9FF995677DB32BCE2E0CD559AE86840EBF4A696872076E37DFFE8F", "k24t - Realtek webOS 9 StanbyME 2 (2024) - HE_DTV_N24D_AFADATAA"),
    ("25DF24166745B52EAB661455BED43DE376320FAA1F7824877B938DB869308B18", "k25lp - Realtek webOS 10 (2025) - HE_DTV_W25P_AFADATAA"),
    ("B2E8C3E214F044B823916E48FA074E606C7C5CD5E6902B6F99BD903DAC0C792F", "k24n - Realtek webOS 10 (2025) - HE_DTV_W25H_AFADATAA"),
    ("B23981FD3642CDF401E7A0C2FADBDA4399B6AAF9600B802144933B4F4E5855EA", "k6lpwee - Realtek webOS 5 (2020) - HE_DTV_C20P_AFADATAA"),
    ("3263653764623932376235323637653637633035363066353833303235383466", "k8lpwee - Realtek webOS 7 (2022) - HE_DTV_C22P_AFADATAA"),
    ("46715DFBDE23C2D8CBA7EC4F36BA41AAD28E7EC00FEC51F2843F24654DB09BD3", "k8hpwee - Realtek webOS 7 (2022) - HE_DTV_C22H_AFABATAA"),
    ("6238323334663232396632613762316537333731333832306664666136333564", "k8apwee - Realtek webOS 7 (2022) - HE_DTV_C22L_AFAAATAA"),
]

MTK_CBC_KEYS: List[Tuple[str, str, str]] = [
    ("09291094092910940929109409291094", "00000000000000000000000000000000", "Mediatek Generic (Hisense, Sharp, Philips)"),
    ("53686172536861725348617253686172", "00000000000000000000000000000000", "SharSharSHarShar (Sharp key for Sharp external partition)"),
    ("5450565F5450565F5450565F5450565F", "00000000000000000000000000000000", "TPVision(Philips) 2012"),
    ("D378EAF81D378A801B556985789A7C31", "73079FD19183715E130858588479C652", "Philips 2012"),
    ("47FBF8CAD62BB95AF3AD9509E5C2175D", "63120FB321B0410F216D6DC2D8641A11", "Philips 2013"),
    ("55555555555555555555555555555555", "B1BFAA407F70C80C650379DFEAFAA40F", "TCL 2017"),
    ("1B569AA7D2E4CCE66584A7A3D8A45679", "A0E88D5D52A813260D3A34A14AA89416", "TPV_MTK2K17PLF_EU0"),
    ("135AFB6DE91CD56496244BC7C0E08D63", "C6A38C89F0AF5637EB6E19D35E12E257", "TPV_MTK2K14PLF_EU1"),
    ("7B17F7764818AE2C897BA69D428D0CB3", "672041CCB9FCD4272B11E57AB6047163", "TPV_MTK2K16PLF_EU0"),
]

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

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
        if self.wvd_generated > 0:
            log.info(f"  WVD files made     : {self.wvd_generated}")
        log.info("─────────────────────────────────────────")

def _check_crypto() -> bool:
    try:
        from Crypto.Cipher import AES as _AES
        return True
    except ImportError:
        return False

HAS_CRYPTO = _check_crypto()

def load_keys_from_file(path: str) -> Tuple[List[Tuple[str,str]], List[Tuple[str,str,str]]]:
    ecb: List[Tuple[str,str]] = []
    cbc: List[Tuple[str,str,str]] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('#', 1)
                key_part = parts[0].strip()
                comment = parts[1].strip() if len(parts) > 1 else 'external'
                if key_part.startswith("b'") or key_part.startswith('b"'):
                    continue
                if ',' in key_part:
                    k, iv = key_part.split(',', 1)
                    k = k.strip().replace(' ','')
                    iv = iv.strip().replace(' ','')
                    try:
                        bytes.fromhex(k)
                        bytes.fromhex(iv)
                        if len(k) >= 32:
                            cbc.append((k.upper(), iv.upper(), comment))
                    except ValueError:
                        pass
                else:
                    k = key_part.replace(' ','')
                    try:
                        bytes.fromhex(k)
                        if len(k) >= 32:
                            ecb.append((k.upper(), comment))
                    except ValueError:
                        pass
    except Exception as e:
        log.warning(f"  Could not load key file {path}: {e}")
    return ecb, cbc

def _aes_ecb_decrypt(data: bytes, key: bytes) -> Optional[bytes]:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        padded = pad(data, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(padded)
    except Exception:
        return None

def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        padded = pad(data, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(padded)
    except Exception:
        return None

def _extract_payload(dec: bytes) -> Optional[bytes]:
    for offset in (64, 96):
        candidate = dec[offset:]
        if b"CHAI" in candidate or b"kbox" in candidate:
            if b"CHAI" in candidate:
                return candidate
            else:
                return candidate[:128]
    return dec[64:]

def try_decrypt(
    blob: bytes,
    manual_key_hex: Optional[str],
    extra_ecb: List[Tuple[str,str]],
    extra_cbc: List[Tuple[str,str,str]],
) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    if not HAS_CRYPTO:
        return None, None, None

    ecb_candidates: List[Tuple[str,str]] = []
    cbc_candidates: List[Tuple[str,str,str]] = []

    if manual_key_hex:
        k = manual_key_hex.replace(' ','').upper()
        ecb_candidates.append((k, 'manual'))

    ecb_candidates.extend(extra_ecb)
    ecb_candidates.extend(AES_ECB_KEYS)
    cbc_candidates.extend(extra_cbc)
    cbc_candidates.extend(MTK_CBC_KEYS)

    for key_hex, desc in ecb_candidates:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            continue
        dec = _aes_ecb_decrypt(blob, key)
        if dec and b"INNER_MSTAR" in dec:
            payload = _extract_payload(dec)
            return payload, key_hex, f"AES-ECB | {desc}"

    for key_hex, iv_hex, desc in cbc_candidates:
        try:
            key = bytes.fromhex(key_hex)
            iv = bytes.fromhex(iv_hex)
        except ValueError:
            continue
        dec = _aes_cbc_decrypt(blob, key, iv)
        if dec and b"INNER_MSTAR" in dec:
            payload = _extract_payload(dec)
            return payload, key_hex, f"AES-CBC | {desc}"

    return None, None, None

def _check_pywidevine() -> bool:
    try:
        import importlib
        importlib.import_module('pywidevine')
        return True
    except ImportError:
        return False

HAS_PYWIDEVINE = _check_pywidevine()

def try_generate_wvd(payload: bytes, out_stem: str, output_dir: str) -> Optional[str]:
    if not HAS_PYWIDEVINE:
        return None

    try:
        import tempfile
        tmpdir = tempfile.mkdtemp()

        payload_path = os.path.join(tmpdir, "payload.bin")
        with open(payload_path, "wb") as f:
            f.write(payload)

        wvd_path = os.path.join(output_dir, f"{out_stem}.wvd")

        result = subprocess.run(
            [sys.executable, "-m", "pywidevine", "create-device",
             "--client-id", payload_path,
             "--type", "ANDROID",
             "--security-level", "1",
             "-o", wvd_path],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0 and os.path.exists(wvd_path):
            return wvd_path

        try:
            from pywidevine.device import Device, DeviceTypes
            from pywidevine.cdm import Cdm
            device = Device.loads(payload)
            device.dump(wvd_path)
            if os.path.exists(wvd_path):
                return wvd_path
        except Exception:
            pass

    except Exception as e:
        log.debug(f"  WVD generation error: {e}")

    return None

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

def out_stem_for_hit(prefix: str, hit_idx: int) -> str:
    return f"{prefix}_Keybox" if hit_idx == 1 else f"{prefix}_Keybox_{hit_idx}"

def write_manifest(entries: list, output_dir: str):
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(entries, f, indent=2)
    log.info(f"\nManifest written -> {manifest_path}")

def extract_from_file(
    path: str,
    prefix: bytes,
    postfixes: List[bytes],
    output_dir: str,
    stats: ScanStats,
    manifest_entries: list,
    verbose_filters: bool = False,
    no_decrypt: bool = False,
    manual_key_hex: Optional[str] = None,
    extra_ecb: Optional[List[Tuple[str,str]]] = None,
    extra_cbc: Optional[List[Tuple[str,str,str]]] = None,
    no_wvd: bool = False,
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
    _extra_ecb = extra_ecb or []
    _extra_cbc = extra_cbc or []

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
                block = bytes(mm[ppos:ppos + EXTRACT_LEN])

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
                stem = out_stem_for_hit(per_file_prefix, saved)
                out_name = os.path.join(output_dir, stem + ".bin")

                with open(out_name, "wb") as out:
                    out.write(block)

                log.info(f"[{os.path.basename(path)} | Hit #{saved}] -> {out_name}  prefix@0x{ppos:X}  postfix@0x{qpos:X}")

                if PRINT_HEXVIEW:
                    log.info(hexview(block, base_offset=ppos, width=HEXVIEW_WIDTH))
                    log.info("")

                manifest_entry: Dict = {
                    "source_file": path,
                    "offset_hex": hex(ppos),
                    "sha256": hashlib.sha256(block).hexdigest(),
                    "keybox_file": out_name,
                    "decrypted": False,
                    "decrypt_key": None,
                    "decrypt_method": None,
                    "payload_file": None,
                    "wvd_file": None,
                }

                if not no_decrypt:
                    if not HAS_CRYPTO:
                        log.warning("  [!] pycryptodome not installed.")
                    else:
                        log.info(f"  [~] Attempting decryption ({len(AES_ECB_KEYS)} ECB + {len(MTK_CBC_KEYS)} CBC keys)...")
                        payload, used_key, used_method = try_decrypt(block, manual_key_hex, _extra_ecb, _extra_cbc)

                        if payload is not None:
                            stats.decrypted += 1
                            payload_path = os.path.join(output_dir, stem + "_payload.bin")
                            with open(payload_path, "wb") as pf:
                                pf.write(payload)
                            log.info(f"  [+] Decrypted  -> {payload_path}")
                            log.info(f"  [+] Key used   : {used_key}")
                            log.info(f"  [+] Method     : {used_method}")

                            manifest_entry["decrypted"] = True
                            manifest_entry["decrypt_key"] = used_key
                            manifest_entry["decrypt_method"] = used_method
                            manifest_entry["payload_file"] = payload_path

                            if not no_wvd:
                                if not HAS_PYWIDEVINE:
                                    log.info("  [i] pywidevine not installed.")
                                    log.info("      Install with: pip install pywidevine")
                                else:
                                    wvd_path = try_generate_wvd(payload, stem, output_dir)
                                    if wvd_path:
                                        stats.wvd_generated += 1
                                        manifest_entry["wvd_file"] = wvd_path
                                        log.info(f"  [+] WVD        -> {wvd_path}")
                                    else:
                                        log.info("  [!] WVD generation failed.")
                        else:
                            stats.decrypt_failed += 1
                            log.info("  [-] No matching decryption key found in database.")
                            log.info("      Use --key <hex> to provide a key manually.")

                manifest_entries.append(manifest_entry)
                log.info("")

                if MAX_HITS and saved >= MAX_HITS:
                    break
        finally:
            mm.close()

    return saved

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="MStarToWVD",
        description="Extract MStar/MediaTek Widevine L1 keyboxes from raw eMMC dumps and firmware images, decrypt them, and generates .wvd files."
    )
    parser.add_argument("files", nargs="*", help="One or more binary files to scan.")
    parser.add_argument("--all", action="store_true", help="Scan all files in the script's directory.")
    parser.add_argument("--output-dir", "-o", default=".", help="Directory to save all output files.")
    parser.add_argument("--no-hexview", action="store_true", help="Remove hex dump output.")
    parser.add_argument("--verbose-filters", action="store_true", help="Log candidate block rejection reasons.")
    parser.add_argument("--quiet", "-q", action="store_true", help="Remove all output except errors.")
    parser.add_argument("--no-decrypt", action="store_true", help="Skip decryption.")
    parser.add_argument("--key", metavar="HEX", help="Manual AES key in hex.")
    parser.add_argument("--keys-file", metavar="FILE", help="Path to an external key database file.")
    parser.add_argument("--no-wvd", action="store_true", help="Skip WVD generation.")

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

    extra_ecb: List[Tuple[str,str]] = []
    extra_cbc: List[Tuple[str,str,str]] = []
    if args.keys_file:
        if not os.path.isfile(args.keys_file):
            log.error(f"Key file not found: {args.keys_file}")
            return 2
        extra_ecb, extra_cbc = load_keys_from_file(args.keys_file)
        log.info(f"Loaded {len(extra_ecb)} ECB + {len(extra_cbc)} CBC keys from {args.keys_file}")

    os.makedirs(args.output_dir, exist_ok=True)
    stats = ScanStats()
    manifest_entries: list = []

    if not args.quiet and not args.no_decrypt:
        if not HAS_CRYPTO:
            log.info("[!] pycryptodome not found! Decryption disabled. Install: pip install pycryptodome")
        if not HAS_PYWIDEVINE and not args.no_wvd:
            log.info("[i] pywidevine not found! WVD generation disabled. Install: pip install pywidevine")
        log.info("")

    kwargs = dict(
        output_dir=args.output_dir,
        stats=stats,
        manifest_entries=manifest_entries,
        verbose_filters=args.verbose_filters,
        no_decrypt=args.no_decrypt,
        manual_key_hex=args.key,
        extra_ecb=extra_ecb,
        extra_cbc=extra_cbc,
        no_wvd=args.no_wvd,
    )

    if args.all:
        total = 0
        for name in sorted(os.listdir(SCRIPT_DIR)):
            path = os.path.join(SCRIPT_DIR, name)
            if not os.path.isfile(path):
                continue
            if is_skipped_file(path):
                continue
            total += extract_from_file(path, prefix, postfixes, **kwargs)
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
            total += extract_from_file(path, prefix, postfixes, **kwargs)
        stats.report()
        if manifest_entries:
            write_manifest(manifest_entries, args.output_dir)
        return 0 if total else 1

    parser.print_help()
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
