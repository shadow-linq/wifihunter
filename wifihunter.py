#!/usr/bin/env python3
"""
WiFi Vulnerability Scanner
Analyzes one or more pcap files for common WiFi security vulnerabilities.

Usage:
    python wifihunter.py capture.pcap [capture2.pcap ...] --ssids SSID1 SSID2
    python wifihunter.py *.pcap --all-ssids

Requirements:
    pip install scapy
"""

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, \
        Dot11Auth, Dot11Deauth, Dot11Disas, EAPOL
    from scapy.layers.eap import EAP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Severity constants
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,   SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: "\033[91m",
    SEVERITY_HIGH:     "\033[31m",
    SEVERITY_MEDIUM:   "\033[93m",
    SEVERITY_LOW:      "\033[94m",
    SEVERITY_INFO:     "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability library
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    vuln_id: str
    severity: str
    title: str
    description: str
    recommendation: str
    references: list = field(default_factory=list)

@dataclass
class Finding:
    ssid: str
    bssid: str
    vulnerability: Vulnerability
    details: str = ""

VULNS = {
    "WEP": Vulnerability(
        vuln_id="WIFI-001",
        severity=SEVERITY_CRITICAL,
        title="WEP Encryption in Use",
        description=(
            "Wired Equivalent Privacy (WEP) is a deprecated and cryptographically broken "
            "protocol. WEP keys can be cracked in minutes using freely available tools "
            "like aircrack-ng regardless of key length. WEP IV reuse (after ~5000 packets) "
            "makes statistical key recovery trivial."
        ),
        recommendation="Migrate to WPA3-Personal or at minimum WPA2-Personal with AES/CCMP.",
        references=["CVE-2001-0161", "https://doi.org/10.1145/508781.508812"],
    ),
    "WPA1": Vulnerability(
        vuln_id="WIFI-002",
        severity=SEVERITY_HIGH,
        title="WPA1 (TKIP) Encryption in Use",
        description=(
            "WPA1 with TKIP is deprecated and vulnerable to the TKIP MIC (Beck-Tews) attack, "
            "the chopchop attack enabling partial plaintext recovery, and KRACK "
            "(Key Reinstallation Attack). TKIP was a stopgap fix for WEP hardware and "
            "retains structural weaknesses inherited from RC4."
        ),
        recommendation="Upgrade to WPA2 or WPA3 using AES/CCMP cipher suite.",
        references=["CVE-2008-2230", "https://papers.mathyvanhoef.com/ccs2017.pdf"],
    ),
    "WPA2_TKIP": Vulnerability(
        vuln_id="WIFI-003",
        severity=SEVERITY_HIGH,
        title="WPA2 with TKIP Cipher Suite Advertised",
        description=(
            "Although WPA2 authentication is in use, the AP advertises TKIP as a supported "
            "pairwise cipher. TKIP is vulnerable to KRACK (CVE-2017-13077/13078) and several "
            "RC4-based weaknesses. Clients that negotiate TKIP are fully exposed."
        ),
        recommendation="Configure AP to advertise only AES/CCMP (cipher suite 4). Remove TKIP entirely.",
        references=["CVE-2017-13077", "CVE-2017-13078"],
    ),
    "PMF_OPTIONAL": Vulnerability(
        vuln_id="WIFI-004",
        severity=SEVERITY_MEDIUM,
        title="Protected Management Frames (PMF) Optional — Not Required",
        description=(
            "PMF (802.11w) is advertised as capable (MFPC=1) but not required (MFPR=0). "
            "Clients that do not negotiate PMF connect without management frame protection, "
            "remaining vulnerable to unauthenticated deauthentication DoS attacks and "
            "evil-twin facilitation."
        ),
        recommendation="Set MFPR=1 (PMF Required) in AP configuration to enforce protection for all clients.",
        references=["IEEE 802.11w-2009", "CVE-2019-16275"],
    ),
    "WPA2_NO_PMF": Vulnerability(
        vuln_id="WIFI-005",
        severity=SEVERITY_HIGH,
        title="WPA2 Network — No PMF Capability Advertised",
        description=(
            "This WPA2 network does not advertise any PMF capability (MFPC=0, MFPR=0). "
            "Deauthentication and disassociation frames are completely unprotected, making "
            "trivial DoS attacks and evil-twin attacks straightforward."
        ),
        recommendation="Enable PMF at minimum as optional; set to Required where all clients support 802.11w.",
        references=["IEEE 802.11w-2009"],
    ),
    "OPEN_AUTH": Vulnerability(
        vuln_id="WIFI-006",
        severity=SEVERITY_CRITICAL,
        title="Open Authentication — No Encryption",
        description=(
            "The network uses open authentication with no encryption. All traffic is transmitted "
            "in plaintext and is trivially interceptable by any nearby wireless device. "
            "Credentials, session tokens, and all data are exposed."
        ),
        recommendation=(
            "Implement WPA3-Personal or WPA2-Personal. For public/guest networks, "
            "deploy WPA3-OWE (Opportunistic Wireless Encryption, RFC 8110) which "
            "provides unauthenticated encryption without a passphrase."
        ),
        references=["IEEE 802.11-2020", "RFC 8110"],
    ),
    "EAP_MSCHAPV2": Vulnerability(
        vuln_id="WIFI-007",
        severity=SEVERITY_HIGH,
        title="EAP-PEAP or EAP-TTLS with Likely MS-CHAPv2 Inner Method",
        description=(
            "PEAP or TTLS was observed, which most commonly tunnels MS-CHAPv2 as the inner "
            "authentication method. MS-CHAPv2 is vulnerable to offline dictionary attacks; "
            "Moxie Marlinspike demonstrated in 2012 that the full MS-CHAPv2 exchange reduces "
            "to a single DES brute-force (at most 2^56 operations). Without strict server "
            "certificate pinning, a rogue AP can harvest credentials via hostapd-wpe."
        ),
        recommendation=(
            "Replace MS-CHAPv2 with EAP-TLS (mutual certificate authentication). "
            "At minimum, enforce server certificate validation with a pinned internal CA "
            "on all supplicants."
        ),
        references=["CVE-2012-2691",
                    "https://www.cloudcracker.com/blog/2012/07/29/cracking-ms-chap-v2/"],
    ),
    "EAP_MD5": Vulnerability(
        vuln_id="WIFI-008",
        severity=SEVERITY_CRITICAL,
        title="EAP-MD5 Authentication",
        description=(
            "EAP-MD5 provides no mutual authentication and is vulnerable to offline dictionary "
            "attacks and man-in-the-middle attacks. RFC 4017 explicitly prohibits EAP-MD5 for "
            "wireless LAN authentication."
        ),
        recommendation="Replace immediately with EAP-TLS, EAP-PEAP, or EAP-TTLS.",
        references=["RFC 4017", "RFC 3748"],
    ),
    "EAP_LEAP": Vulnerability(
        vuln_id="WIFI-009",
        severity=SEVERITY_CRITICAL,
        title="LEAP (Cisco Lightweight EAP) Authentication",
        description=(
            "LEAP uses MS-CHAPv1 which is entirely broken. A single captured LEAP exchange "
            "is sufficient to recover the plaintext password using asleap. No dictionary is "
            "required for weak passwords."
        ),
        recommendation="Disable LEAP and migrate to EAP-TLS or PEAP with proper certificate validation.",
        references=["https://www.willhackforsushi.com/papers/asleap-wpe.pdf"],
    ),
    "EAP_FAST_ANON": Vulnerability(
        vuln_id="WIFI-010",
        severity=SEVERITY_MEDIUM,
        title="EAP-FAST Observed — Anonymous PAC Provisioning Risk",
        description=(
            "EAP-FAST was observed. In anonymous PAC provisioning mode (Phase 0), a rogue AP "
            "can provision a malicious PAC credential to an unsuspecting client, enabling "
            "subsequent credential theft during Phase 1 authentication."
        ),
        recommendation="Use authenticated PAC provisioning or replace with EAP-TLS.",
        references=["RFC 4851"],
    ),
    "DEAUTH_FLOOD": Vulnerability(
        vuln_id="WIFI-011",
        severity=SEVERITY_MEDIUM,
        title="Deauthentication / Disassociation Frame Flood Detected",
        description=(
            "A high volume of deauthentication or disassociation frames was observed targeting "
            "this BSSID. This strongly indicates either a deauth-flood denial-of-service attack "
            "or an active evil-twin/KARMA attack attempting to force client reconnection to "
            "a rogue AP."
        ),
        recommendation=(
            "Enable PMF (802.11w) Required to cryptographically authenticate management frames. "
            "Enable rogue AP and deauth flood detection on your wireless infrastructure."
        ),
        references=["IEEE 802.11w-2009", "CVE-2019-16275"],
    ),
    "WPS_ENABLED": Vulnerability(
        vuln_id="WIFI-012",
        severity=SEVERITY_HIGH,
        title="WPS (Wi-Fi Protected Setup) Enabled",
        description=(
            "WPS is enabled on this AP. The WPS PIN method has a design flaw allowing the "
            "8-digit PIN to be brute-forced in at most ~11,000 attempts (Viehboeck, 2011). "
            "The Pixie-Dust attack (Dominique Bongard, 2014) can recover the PIN instantly "
            "against many chipset implementations by exploiting weak nonce generation."
        ),
        recommendation="Disable WPS entirely. There is no secure way to run WPS PIN mode.",
        references=["CVE-2011-5053", "CVE-2014-9486",
                    "https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf"],
    ),
    "SSID_BROADCAST": Vulnerability(
        vuln_id="WIFI-013",
        severity=SEVERITY_INFO,
        title="SSID Actively Broadcasting",
        description=(
            "The network is actively broadcasting its SSID in beacon frames "
            "(wlan.ssid_len > 0 in beacon, subtype 0x08). This is normal and expected "
            "for most networks, but is noted here for inventory purposes. Any device "
            "within radio range can passively enumerate this network name without "
            "sending any frames."
        ),
        recommendation=(
            "No action required for most deployments. If this is a sensitive internal "
            "network that should not be discoverable, consider whether SSID suppression "
            "is appropriate — though note it provides no real security benefit and "
            "causes clients to actively probe for the SSID name in public."
        ),
        references=["IEEE 802.11-2020"],
    ),
    "KRACK": Vulnerability(
        vuln_id="WIFI-014",
        severity=SEVERITY_HIGH,
        title="KRACK Vulnerability Indicators (WPA2 + TKIP, No Required PMF)",
        description=(
            "The combination of TKIP cipher support and absence of required PMF indicates "
            "exposure to KRACK (Key Reinstallation Attack, CVE-2017-13077 through 13088). "
            "KRACK allows an attacker within radio range to replay handshake messages, "
            "causing nonce reuse and enabling decryption, replay, and forgery of frames."
        ),
        recommendation=(
            "Apply OS/firmware patches for all KRACK CVEs. Disable TKIP cipher. "
            "Enable PMF Required."
        ),
        references=["CVE-2017-13077", "https://www.krackattacks.com/"],
    ),
    "WPA3_DRAGONBLOOD": Vulnerability(
        vuln_id="WIFI-015",
        severity=SEVERITY_MEDIUM,
        title="WPA3-SAE Transition Mode Without PMF Required — Dragonblood Downgrade Risk",
        description=(
            "This AP advertises both WPA2 (PSK) and WPA3 (SAE) AKMs simultaneously "
            "(transition mode) without setting PMF as Required. Vanhoef and Ronen's "
            "Dragonblood research (2019) demonstrated that without mandatory PMF, an "
            "attacker can operate a rogue AP advertising only WPA2-PSK, causing clients "
            "to downgrade from SAE to PSK. The resulting WPA2 handshake is then "
            "vulnerable to offline dictionary attacks, entirely defeating the security "
            "benefit of WPA3-SAE. The Wi-Fi Alliance WPA3 specification (section 3.3) "
            "mandates PMF Required in transition mode precisely to close this downgrade path."
        ),
        recommendation=(
            "Set PMF to Required (MFPR=1) in the RSN IE. Alternatively, disable transition "
            "mode and run WPA3-SAE only if all clients support it. Apply vendor firmware "
            "patches for CVE-2019-9494 and CVE-2019-9496."
        ),
        references=[
            "CVE-2019-9494",
            "CVE-2019-9496",
            "https://wpa3.mathyvanhoef.com/",
            "https://www.wi-fi.org/security-update-april-2019",
        ],
    ),
    "EAP_NO_SERVER_CERT": Vulnerability(
        vuln_id="WIFI-016",
        severity=SEVERITY_HIGH,
        title="Enterprise (802.1X/EAP) Network — Client Certificate Validation Risk",
        description=(
            "An 802.1X Enterprise EAP network is present. Without strict server certificate "
            "validation configured on every supplicant (with a pinned internal CA), any user "
            "can be silently redirected to a rogue AP running hostapd-wpe or a similar tool, "
            "which harvests credentials from the EAP exchange without the user's knowledge."
        ),
        recommendation=(
            "Enforce server certificate validation on all supplicants. Pin a specific "
            "internal CA certificate and disable user prompts to accept unknown certificates. "
            "Use MDM/GPO to push validated 802.1X profiles."
        ),
        references=["https://www.securew2.com/blog/evil-twin-attack"],
    ),
    "PMKID_CAPTURABLE": Vulnerability(
        vuln_id="WIFI-017",
        severity=SEVERITY_MEDIUM,
        title="PMKID Offline Crack Exposure (WPA2-Personal)",
        description=(
            "WPA2-Personal networks expose the PMKID in the first EAPOL frame of the 4-way "
            "handshake, allowing offline password cracking without requiring a full handshake "
            "or any connected client (Jens Steube, 2018)."
        ),
        recommendation=(
            "Use a passphrase of 20+ random characters to make offline cracking infeasible. "
            "Migrate to WPA3-SAE, which uses the Dragonfly handshake and is not vulnerable "
            "to PMKID-based offline attacks."
        ),
        references=["https://hashcat.net/forum/thread-7717.html"],
    ),
    "HANDSHAKE_CAPTURED": Vulnerability(
        vuln_id="WIFI-018",
        severity=SEVERITY_MEDIUM,
        title="WPA2 4-Way Handshake Captured — Offline Dictionary Attack Possible",
        description=(
            "A WPA2 4-way handshake was observed in the capture. This handshake contains "
            "enough information to conduct an offline dictionary or brute-force attack "
            "against the network passphrase using tools like hashcat or aircrack-ng."
        ),
        recommendation=(
            "Use a strong, randomly generated passphrase of 20+ characters. "
            "Migrate to WPA3-SAE for forward secrecy and resistance to offline cracking."
        ),
        references=["https://www.aircrack-ng.org/"],
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# 802.11 / RSN constants
# ─────────────────────────────────────────────────────────────────────────────

RSN_CAP_MFPR = 0x0040
RSN_CAP_MFPC = 0x0080

AKM_8021X        = 1
AKM_PSK          = 2
AKM_FT_1X        = 3
AKM_FT_PSK       = 4
AKM_8021X_SHA256 = 5
AKM_PSK_SHA256   = 6
AKM_SAE          = 8
AKM_OWE          = 18

CIPHER_TKIP = 2
CIPHER_CCMP = 4

# Dot11 FCfield protected bit
FC_PROTECTED = 0x40

EAP_TYPE_NAMES = {
    1: "Identity", 3: "NAK", 4: "MD5", 13: "TLS",
    17: "LEAP",    21: "TTLS", 25: "PEAP", 43: "FAST",
}

DEAUTH_FLOOD_THRESHOLD = 10

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class APInfo:
    ssid: str
    bssid: str
    has_wep: bool = False
    has_wpa1: bool = False
    has_wpa2: bool = False
    has_wpa3: bool = False
    has_owe: bool = False
    is_open: bool = False
    ssid_broadcast: bool = False   # True if SSID IE in beacon is non-empty
    has_wps: bool = False
    cap_privacy: bool = False
    # Number of data frames with the protected FC bit set, for this BSSID.
    # Used to disambiguate WEP from open networks on modern APs that may
    # set the privacy bit in beacons under edge cases.
    protected_data_frames: int = 0
    wpa2_rsn: Optional[dict] = None
    wpa1_info: Optional[dict] = None
    wpa3_transition: bool = False
    eap_types_seen: set = field(default_factory=set)
    eapol_frames: list = field(default_factory=list)
    deauth_count: int = 0
    disas_count: int = 0
    seen_in_pcaps: set = field(default_factory=set)

# ─────────────────────────────────────────────────────────────────────────────
# IE / frame parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def parse_rsn_ie(data: bytes) -> dict:
    result = {
        "version": 0, "group_cipher": None, "pairwise_ciphers": [],
        "akm_suites": [], "capabilities": 0,
        "pmf_capable": False, "pmf_required": False,
    }
    if len(data) < 2:
        return result
    idx = 2
    if idx + 4 > len(data): return result
    result["group_cipher"] = data[idx + 3]
    idx += 4
    if idx + 2 > len(data): return result
    pc = int.from_bytes(data[idx:idx+2], "little"); idx += 2
    for _ in range(pc):
        if idx + 4 > len(data): break
        result["pairwise_ciphers"].append(data[idx+3]); idx += 4
    if idx + 2 > len(data): return result
    ac = int.from_bytes(data[idx:idx+2], "little"); idx += 2
    for _ in range(ac):
        if idx + 4 > len(data): break
        result["akm_suites"].append(data[idx+3]); idx += 4
    if idx + 2 <= len(data):
        caps = int.from_bytes(data[idx:idx+2], "little")
        result["capabilities"] = caps
        result["pmf_capable"]  = bool(caps & RSN_CAP_MFPC)
        result["pmf_required"] = bool(caps & RSN_CAP_MFPR)
    return result

def parse_wpa1_ie(data: bytes) -> dict:
    result = {"pairwise_ciphers": [], "akm_suites": []}
    if len(data) < 2: return result
    idx = 2
    if idx + 4 > len(data): return result
    idx += 4
    if idx + 2 > len(data): return result
    pc = int.from_bytes(data[idx:idx+2], "little"); idx += 2
    for _ in range(pc):
        if idx + 4 > len(data): break
        result["pairwise_ciphers"].append(data[idx+3]); idx += 4
    if idx + 2 > len(data): return result
    ac = int.from_bytes(data[idx:idx+2], "little"); idx += 2
    for _ in range(ac):
        if idx + 4 > len(data): break
        result["akm_suites"].append(data[idx+3]); idx += 4
    return result

def iter_ies(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt and isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

def get_ssid_and_bssid(pkt):
    bssid = pkt[Dot11].addr3 if pkt.haslayer(Dot11) else None
    ssid = None
    for elt in iter_ies(pkt):
        if elt.ID == 0:
            try:    ssid = elt.info.decode("utf-8", errors="replace")
            except: ssid = ""
            break
    return ssid, bssid

# ─────────────────────────────────────────────────────────────────────────────
# Per-pcap analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: str, target_ssids: Optional[list],
                 all_ssids: bool, aps: dict) -> dict:
    """Parse one pcap and merge results into the shared aps dict."""
    print(f"[*] Loading: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"    [!] Failed to read: {e}")
        return aps
    print(f"    {len(packets)} packets")

    target_set = {s.lower() for s in target_ssids} if target_ssids else set()

    def should_include(ssid: str) -> bool:
        if all_ssids: return True
        if not target_set: return True
        return ssid.lower() in target_set

    deauth_counts:  dict = defaultdict(int)
    disas_counts:   dict = defaultdict(int)
    eapol_by_bssid: dict = defaultdict(list)
    eap_by_bssid:   dict = defaultdict(set)
    # Data frames with the protected FC bit set, keyed by BSSID
    protected_data: dict = defaultdict(int)

    # ── Pass 1: Beacons & Probe Responses ────────────────────────────────────
    for pkt in packets:
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            continue
        ssid, bssid = get_ssid_and_bssid(pkt)
        if ssid is None or bssid is None: continue
        if not should_include(ssid): continue

        key = (ssid, bssid.lower())
        if key not in aps:
            aps[key] = APInfo(ssid=ssid, bssid=bssid.lower())
        ap = aps[key]
        ap.seen_in_pcaps.add(pcap_path)

        cap_layer = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
        cap_val   = int(cap_layer.cap) if not isinstance(cap_layer.cap, int) else cap_layer.cap
        ap.cap_privacy = bool(cap_val & 0x0010)
        if not ap.cap_privacy:
            ap.is_open = True

        for elt in iter_ies(pkt):
            if elt.ID == 0:
                # ssid_broadcast = True when the SSID IE has a non-empty, non-null name.
                # Wireshark equivalent: wlan.ssid_len > 0 on beacon frames (subtype 0x08).
                if len(elt.info) > 0 and not all(b == 0 for b in elt.info):
                    ap.ssid_broadcast = True
            elif elt.ID == 48 and len(elt.info) >= 2:
                rsn = parse_rsn_ie(bytes(elt.info))
                if rsn["akm_suites"] or ap.wpa2_rsn is None:
                    ap.wpa2_rsn = rsn
                for akm in rsn["akm_suites"]:
                    if akm == AKM_SAE:   ap.has_wpa3 = True
                    elif akm == AKM_OWE: ap.has_owe  = True
                    elif akm in (AKM_PSK, AKM_PSK_SHA256, AKM_FT_PSK,
                                 AKM_8021X, AKM_8021X_SHA256, AKM_FT_1X):
                        ap.has_wpa2 = True
                if ap.has_wpa3 and ap.has_wpa2:
                    ap.wpa3_transition = True
            elif elt.ID == 221 and len(elt.info) >= 4:
                oui   = bytes(elt.info[:3])
                type_ = elt.info[3] if len(elt.info) > 3 else 0
                if oui == b'\x00\x50\xf2' and type_ == 0x01:
                    ap.has_wpa1  = True
                    ap.wpa1_info = parse_wpa1_ie(bytes(elt.info[4:]))
                elif oui == b'\x00\x50\xf2' and type_ == 0x04:
                    ap.has_wps = True

    # ── Pass 2: Data frames — check protected FC bit ──────────────────────────
    # We require actual protected data frames before calling something WEP.
    # This prevents false positives on modern APs (e.g. Ubiquiti) that may set
    # the beacon privacy bit without using WEP (OWE transition, edge cases).
    for pkt in packets:
        if not pkt.haslayer(Dot11): continue
        d = pkt[Dot11]
        if d.type != 2: continue           # not a data frame
        bssid = d.addr3
        if not bssid: continue
        fc = int(d.FCfield) if not isinstance(d.FCfield, int) else d.FCfield
        if fc & FC_PROTECTED:
            protected_data[bssid.lower()] += 1

    # ── Pass 3: Management frame counts ──────────────────────────────────────
    for pkt in packets:
        if pkt.haslayer(Dot11Deauth):
            b = pkt[Dot11].addr3
            if b: deauth_counts[b.lower()] += 1
        elif pkt.haslayer(Dot11Disas):
            b = pkt[Dot11].addr3
            if b: disas_counts[b.lower()] += 1

    # ── Pass 4: EAPOL / EAP ──────────────────────────────────────────────────
    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            b = pkt[Dot11].addr3
            if b: eapol_by_bssid[b.lower()].append(pkt)
        if pkt.haslayer(EAP) and pkt.haslayer(Dot11):
            b = pkt[Dot11].addr3
            if b and hasattr(pkt[EAP], 'type'):
                eap_by_bssid[b.lower()].add(pkt[EAP].type)

    # ── Merge into AP records ─────────────────────────────────────────────────
    for key, ap in aps.items():
        b = ap.bssid
        ap.deauth_count          += deauth_counts.get(b, 0)
        ap.disas_count           += disas_counts.get(b, 0)
        ap.eapol_frames          += eapol_by_bssid.get(b, [])
        ap.eap_types_seen        |= eap_by_bssid.get(b, set())
        ap.protected_data_frames += protected_data.get(b, 0)

        # WEP determination (deferred until after all passes):
        #   Require privacy bit set AND no WPA/RSN IE AND protected data frames observed.
        #   Without the data-frame check, modern APs that legitimately set the privacy
        #   bit in edge cases (e.g. certain Ubiquiti firmware versions) are falsely flagged.
        if (ap.cap_privacy
                and not ap.has_wpa1
                and not ap.has_wpa2
                and not ap.has_wpa3
                and ap.protected_data_frames > 0):
            ap.has_wep = True
        elif (not ap.cap_privacy
              and not ap.has_wpa1
              and not ap.has_wpa2
              and not ap.has_wpa3
              and not ap.has_wep):
            ap.is_open = True

    return aps

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_vulnerabilities(ap: APInfo) -> list:
    findings = []

    def add(vuln_id: str, details: str = ""):
        findings.append(Finding(ssid=ap.ssid, bssid=ap.bssid,
                                vulnerability=VULNS[vuln_id], details=details))

    if ap.is_open and not any([ap.has_wpa2, ap.has_wpa3, ap.has_wpa1, ap.has_wep]):
        add("OPEN_AUTH")

    if ap.has_wep:
        add("WEP",
            f"Privacy bit set in beacon, no WPA/RSN IE, "
            f"{ap.protected_data_frames} protected data frames observed")

    if ap.has_wpa1 and not ap.has_wpa2 and not ap.has_wpa3:
        ciphers = ap.wpa1_info.get("pairwise_ciphers", []) if ap.wpa1_info else []
        add("WPA1", f"Pairwise ciphers: {ciphers}" if ciphers else "")

    if ap.has_wpa2 and ap.wpa2_rsn:
        rsn      = ap.wpa2_rsn
        pairwise = rsn.get("pairwise_ciphers", [])
        akms     = rsn.get("akm_suites", [])

        if CIPHER_TKIP in pairwise:
            add("WPA2_TKIP", f"Pairwise ciphers: {pairwise}")

        if not rsn.get("pmf_capable"):
            add("WPA2_NO_PMF")
        elif not rsn.get("pmf_required"):
            add("PMF_OPTIONAL")

        if CIPHER_TKIP in pairwise and not rsn.get("pmf_required"):
            add("KRACK", "TKIP cipher present and PMF not required")

        enterprise = {AKM_8021X, AKM_8021X_SHA256, AKM_FT_1X}
        if any(a in enterprise for a in akms):
            add("EAP_NO_SERVER_CERT")

        personal = {AKM_PSK, AKM_PSK_SHA256, AKM_FT_PSK}
        if any(a in personal for a in akms):
            add("PMKID_CAPTURABLE")

        if len(ap.eapol_frames) >= 2:
            add("HANDSHAKE_CAPTURED",
                f"{len(ap.eapol_frames)} EAPOL frames captured across all pcaps")

    if ap.has_wpa3 and ap.wpa3_transition and ap.wpa2_rsn:
        if not ap.wpa2_rsn.get("pmf_required"):
            add("WPA3_DRAGONBLOOD",
                "Transition mode: WPA2+WPA3 AKMs in same RSN IE, MFPR=0")

    if ap.has_wps:
        add("WPS_ENABLED")

    if ap.ssid_broadcast:
        add("SSID_BROADCAST", f"SSID '{ap.ssid}' visible in beacon frames (wlan.ssid_len > 0)")

    total_mgmt = ap.deauth_count + ap.disas_count
    if total_mgmt >= DEAUTH_FLOOD_THRESHOLD:
        add("DEAUTH_FLOOD",
            f"{ap.deauth_count} deauth + {ap.disas_count} disas frames across all pcaps")

    for eap_type in ap.eap_types_seen:
        name = EAP_TYPE_NAMES.get(eap_type, f"type {eap_type}")
        if eap_type == 4:
            add("EAP_MD5",      "EAP-MD5 observed in authentication exchange")
        elif eap_type == 17:
            add("EAP_LEAP",     "LEAP observed in authentication exchange")
        elif eap_type in (21, 25):
            add("EAP_MSCHAPV2", f"EAP-{name} observed; inner method likely MS-CHAPv2")
        elif eap_type == 43:
            add("EAP_FAST_ANON","EAP-FAST observed; verify PAC provisioning mode")

    # Deduplicate by vuln_id (keep first occurrence)
    seen, unique = set(), []
    for f in findings:
        if f.vulnerability.vuln_id not in seen:
            seen.add(f.vulnerability.vuln_id)
            unique.append(f)
    return unique

# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def _wrap(text: str, width: int) -> list:
    words = text.split(); lines = []; line = []; length = 0
    for word in words:
        if length + len(word) + 1 > width:
            lines.append(" ".join(line)); line = [word]; length = len(word)
        else:
            line.append(word); length += len(word) + 1
    if line: lines.append(" ".join(line))
    return lines

def print_findings(all_findings: dict, ap_map: dict, use_color: bool = True):
    col = SEVERITY_COLORS if use_color else {k: "" for k in SEVERITY_COLORS}
    rst = RESET if use_color else ""
    bld = BOLD  if use_color else ""

    total = sum(len(v) for v in all_findings.values())
    if total == 0:
        print("\n[✓] No vulnerabilities detected."); return

    print(f"\n{'='*70}")
    print(f"{bld}WiFi Vulnerability Report{rst}")
    print(f"{'='*70}")

    for (ssid, bssid), findings in sorted(all_findings.items()):
        if not findings: continue
        ap      = ap_map.get((ssid, bssid))
        label   = ssid if ssid else "(hidden)"
        pcaps   = sorted(ap.seen_in_pcaps) if ap else []
        pcap_note = f"  [seen in: {', '.join(pcaps)}]" if pcaps else ""

        print(f"\n{bld}SSID: {label}  ({bssid}){rst}{pcap_note}")
        print(f"{'─'*70}")

        for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x.vulnerability.severity]):
            v = f.vulnerability
            c = col.get(v.severity, "")
            print(f"\n  {c}[{v.severity}]{rst} {bld}{v.vuln_id} – {v.title}{rst}")
            print(f"  {'─'*60}")
            for line in _wrap(v.description, 64):
                print(f"    {line}")
            if f.details:
                print(f"\n  {bld}Evidence:{rst} {f.details}")
            print(f"\n  {bld}Recommendation:{rst}")
            for line in _wrap(v.recommendation, 64):
                print(f"    {line}")
            if v.references:
                print(f"\n  {bld}References:{rst} {', '.join(v.references[:3])}")

    print(f"\n{'='*70}")
    print(f"{bld}Summary{rst}")
    print(f"{'─'*70}")
    sev_counts: dict = defaultdict(int)
    for findings in all_findings.values():
        for f in findings: sev_counts[f.vulnerability.severity] += 1
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        if sev_counts[sev]:
            c = col.get(sev, "")
            print(f"  {c}{sev:<10}{rst}: {sev_counts[sev]}")
    print(f"  {'─'*20}")
    print(f"  {'TOTAL':<10}: {total}")
    print(f"{'='*70}\n")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global DEAUTH_FLOOD_THRESHOLD
    parser = argparse.ArgumentParser(
        description="WiFi Vulnerability Scanner — analyze one or more pcap files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wifi_vuln_scanner.py capture.pcap --ssids "CorpWifi" "CorpGuest"
  python wifi_vuln_scanner.py morning.pcap afternoon.pcap evening.pcap --ssids "HomeNet"
  python wifi_vuln_scanner.py *.pcap --all-ssids
  python wifi_vuln_scanner.py capture.pcap --all-ssids --no-color
        """
    )
    parser.add_argument(
        "pcaps", nargs="+", metavar="PCAP",
        help="One or more pcap/pcapng files to analyze",
    )
    parser.add_argument(
        "--ssids", nargs="+", metavar="SSID",
        help="Target SSIDs to analyze (space-separated, case-insensitive)",
    )
    parser.add_argument(
        "--all-ssids", action="store_true",
        help="Analyze all SSIDs found across all pcaps",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output",
    )
    parser.add_argument(
        "--deauth-threshold", type=int, default=DEAUTH_FLOOD_THRESHOLD,
        help=f"Deauth+disas frame count threshold for flood detection (default: {DEAUTH_FLOOD_THRESHOLD})",
    )

    args = parser.parse_args()

    if not args.ssids and not args.all_ssids:
        print("[!] Specify --ssids <SSID...> or --all-ssids")
        parser.print_help()
        sys.exit(1)

    DEAUTH_FLOOD_THRESHOLD = args.deauth_threshold

    aps: dict = {}
    for pcap_path in args.pcaps:
        aps = analyze_pcap(pcap_path, args.ssids, args.all_ssids, aps)

    if not aps:
        print("[!] No matching SSIDs found in any of the provided pcap files.")
        sys.exit(0)

    print(f"\n[*] {len(aps)} unique AP(s) found across {len(args.pcaps)} pcap file(s)")

    all_findings: dict = {}
    for key, ap in sorted(aps.items()):
        findings = detect_vulnerabilities(ap)
        all_findings[key] = findings
        label  = ap.ssid or "(hidden)"
        result = f"{len(findings)} finding(s)" if findings else "clean"
        pcap_n = len(ap.seen_in_pcaps)
        print(f"    → {label} [{ap.bssid}]: {result}  "
              f"(seen in {pcap_n} pcap{'s' if pcap_n != 1 else ''})")

    print_findings(all_findings, aps, use_color=not args.no_color)

if __name__ == "__main__":
    main()
