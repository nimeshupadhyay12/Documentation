"""
core/threat_feed.py  -  Anomaly Hunter Pro
============================================
Live threat intelligence feed manager.

Free feeds (no API key needed):
  - Abuse.ch URLhaus     — malicious URLs and domains
  - Abuse.ch ThreatFox   — IOCs with actor tags
  - Abuse.ch MalwareBazaar — file hash intel

Optional (API key needed):
  - AlienVault OTX       — set OTX_API_KEY env var
  - VirusTotal           — set VT_API_KEY env var
  - AbuseIPDB            — set ABUSEIPDB_KEY env var

Feed data is cached locally in feeds/ directory.
Cache TTL: 24 hours (configurable via AH_FEED_TTL env var).
"""

import os
import json
import gzip
import logging
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

log = logging.getLogger("AnomalyHunter.ThreatFeed")

FEED_DIR = Path(__file__).resolve().parent.parent / "feeds"
FEED_TTL = int(os.getenv("AH_FEED_TTL", "86400"))     # 24h default
OTX_KEY  = os.getenv("OTX_API_KEY", "")
VT_KEY   = os.getenv("VT_API_KEY", "")
ABUSE_KEY= os.getenv("ABUSEIPDB_KEY", "")
REQUEST_TIMEOUT = 12


def _cache_path(name: str) -> Path:
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    return FEED_DIR / f"{name}.json"


def _is_fresh(cache_file: Path) -> bool:
    if not cache_file.exists():
        return False
    age = datetime.now().timestamp() - cache_file.stat().st_mtime
    return age < FEED_TTL


def _save_cache(name: str, data: dict):
    p = _cache_path(name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _load_cache(name: str) -> dict:
    p = _cache_path(name)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _http_get(url: str, headers: dict = None, data: bytes = None,
              method: str = "GET") -> bytes:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    req.add_header("User-Agent", "AnomalyHunterPro/1.0")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
        return r.read()


# ── Feed loaders ──────────────────────────────────────────────────────────────

def load_urlhaus_domains() -> set:
    """
    Abuse.ch URLhaus — malicious domains.
    Returns set of known-bad domain strings.
    """
    cache_name = "urlhaus_domains"
    if _is_fresh(_cache_path(cache_name)):
        cached = _load_cache(cache_name)
        return set(cached.get("domains", []))

    log.info("Fetching URLhaus domain feed...")
    domains = set()
    try:
        data = _http_get(
            "https://urlhaus.abuse.ch/downloads/text/",
        )
        for line in data.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(line if "://" in line else "http://" + line)
                    dom = parsed.netloc.split(":")[0].lower()
                    if dom:
                        domains.add(dom)
                except Exception:
                    pass
        _save_cache(cache_name, {"domains": list(domains),
                                  "updated": datetime.now().isoformat()})
        log.info("URLhaus: loaded %d domains", len(domains))
    except Exception as e:
        log.warning("URLhaus feed failed: %s", e)
        # Try cached (even if stale)
        cached = _load_cache(cache_name)
        domains = set(cached.get("domains", []))

    return domains


def load_threatfox_iocs() -> dict:
    """
    Abuse.ch ThreatFox — IOCs with malware family tags.
    Returns dict: {ioc_value: {verdict, malware, confidence}}
    """
    cache_name = "threatfox_iocs"
    if _is_fresh(_cache_path(cache_name)):
        cached = _load_cache(cache_name)
        return cached.get("iocs", {})

    log.info("Fetching ThreatFox IOC feed...")
    iocs = {}
    try:
        payload = json.dumps({"query": "get_iocs", "days": 3}).encode()
        raw = _http_get(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Content-Type": "application/json"},
            data=payload,
            method="POST",
        )
        data = json.loads(raw)
        if data.get("query_status") == "ok":
            for item in data.get("data", []):
                ioc_val = str(item.get("ioc_value", "")).lower()
                if ioc_val:
                    iocs[ioc_val] = {
                        "verdict":    "Malicious",
                        "malware":    item.get("malware", ""),
                        "confidence": int(item.get("confidence_level", 75)),
                        "tags":       f"ThreatFox:{item.get('malware','')}",
                    }
        _save_cache(cache_name, {"iocs": iocs,
                                  "updated": datetime.now().isoformat()})
        log.info("ThreatFox: loaded %d IOCs", len(iocs))
    except Exception as e:
        log.warning("ThreatFox feed failed: %s", e)
        cached = _load_cache(cache_name)
        iocs = cached.get("iocs", {})

    return iocs


def load_malwarebazaar_hashes() -> dict:
    """
    Abuse.ch MalwareBazaar — recent malware hashes.
    Returns dict: {sha256: {verdict, malware_family, tags}}
    """
    cache_name = "malwarebazaar"
    if _is_fresh(_cache_path(cache_name)):
        cached = _load_cache(cache_name)
        return cached.get("hashes", {})

    log.info("Fetching MalwareBazaar hash feed...")
    hashes = {}
    try:
        payload = json.dumps({"query": "get_recent", "selector": "100"}).encode()
        raw = _http_get(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Content-Type": "application/json"},
            data=payload,
            method="POST",
        )
        data = json.loads(raw)
        if data.get("query_status") == "ok":
            for item in data.get("data", []):
                for hash_field in ("sha256_hash", "md5_hash"):
                    h = str(item.get(hash_field, "")).lower()
                    if h:
                        hashes[h] = {
                            "verdict":    "Malicious",
                            "malware":    item.get("signature", ""),
                            "confidence": 90,
                            "tags":       f"MalwareBazaar:{item.get('tags','')}",
                        }
        _save_cache(cache_name, {"hashes": hashes,
                                  "updated": datetime.now().isoformat()})
        log.info("MalwareBazaar: loaded %d hashes", len(hashes))
    except Exception as e:
        log.warning("MalwareBazaar feed failed: %s", e)
        cached = _load_cache(cache_name)
        hashes = cached.get("hashes", {})

    return hashes


def load_otx_iocs() -> dict:
    """AlienVault OTX pulse IOCs (requires OTX_API_KEY)."""
    if not OTX_KEY:
        return {}

    cache_name = "otx_iocs"
    if _is_fresh(_cache_path(cache_name)):
        cached = _load_cache(cache_name)
        return cached.get("iocs", {})

    log.info("Fetching OTX pulse feed...")
    iocs = {}
    try:
        raw = _http_get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
            headers={"X-OTX-API-KEY": OTX_KEY},
        )
        data = json.loads(raw)
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                val  = str(indicator.get("indicator", "")).lower()
                itype = indicator.get("type", "")
                if val:
                    iocs[val] = {
                        "verdict":    "Malicious",
                        "malware":    pulse.get("name", ""),
                        "confidence": 80,
                        "tags":       f"OTX:{pulse.get('name','')},{itype}",
                    }
        _save_cache(cache_name, {"iocs": iocs,
                                  "updated": datetime.now().isoformat()})
        log.info("OTX: loaded %d IOCs", len(iocs))
    except Exception as e:
        log.warning("OTX feed failed: %s", e)

    return iocs


# ── Feed-backed TI enrichment ─────────────────────────────────────────────────

class FeedManager:
    """
    Manages all threat intel feeds and provides fast O(1) IOC lookup.
    Call load_all_feeds() once at startup, then lookup() for each IOC.
    """

    def __init__(self):
        self.domains:  set  = set()
        self.iocs:     dict = {}
        self.hashes:   dict = {}
        self.loaded:   bool = False

    def load_all_feeds(self, offline: bool = False):
        """
        Load all available feeds.
        offline=True: only use cached data, no network requests.
        """
        if offline:
            log.info("Feed manager: offline mode — using cached data only")
            self.domains = set(_load_cache("urlhaus_domains").get("domains", []))
            self.iocs    = _load_cache("threatfox_iocs").get("iocs", {})
            self.hashes  = _load_cache("malwarebazaar").get("hashes", {})
        else:
            self.domains = load_urlhaus_domains()
            self.iocs    = load_threatfox_iocs()
            self.hashes  = load_malwarebazaar_hashes()
            otx = load_otx_iocs()
            self.iocs.update(otx)

        # Merge hashes into iocs lookup
        self.iocs.update(self.hashes)
        self.loaded = True
        log.info("Feed manager ready: %d domains, %d IOCs",
                 len(self.domains), len(self.iocs))

    def lookup(self, ioc_type: str, ioc_value: str) -> dict:
        """
        Look up an IOC. Returns enrichment dict or empty.
        """
        val = str(ioc_value).lower()

        if ioc_type == "Domain":
            # Exact match
            if val in self.iocs:
                return self.iocs[val]
            # Check URLhaus domain list
            if val in self.domains:
                return {"verdict": "Malicious", "tags": "URLhaus", "confidence": 85}
            # Check if any subdomain matches
            parts = val.split(".")
            for i in range(len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.domains:
                    return {"verdict": "Malicious", "tags": f"URLhaus:{parent}", "confidence": 75}

        elif ioc_type == "IP":
            if val in self.iocs:
                return self.iocs[val]

        elif ioc_type == "Hash":
            if val in self.iocs:
                return self.iocs[val]

        elif ioc_type == "URL":
            if val in self.iocs:
                return self.iocs[val]
            # Check if domain portion matches
            try:
                from urllib.parse import urlparse
                dom = urlparse(val).netloc.split(":")[0].lower()
                if dom in self.domains:
                    return {"verdict": "Malicious", "tags": "URLhaus", "confidence": 80}
            except Exception:
                pass

        return {}

    def enrich_ioc_df(self, ioc_df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich an IOC DataFrame with feed-based threat intelligence.
        Adds/updates TI Verdict, TI Tags, TI Confidence columns.
        """
        if ioc_df.empty or not self.loaded:
            return ioc_df

        df = ioc_df.copy()
        verdicts, tags_list, confidences = [], [], []

        for _, row in df.iterrows():
            ioc_type  = str(row.get("IOC Type", ""))
            ioc_value = str(row.get("IOC Value", ""))
            result    = self.lookup(ioc_type, ioc_value)

            # Keep existing verdict if higher confidence
            existing_conf = int(row.get("TI Confidence", 0))
            new_conf      = result.get("confidence", 0)

            if result and new_conf >= existing_conf:
                verdicts.append(result.get("verdict", "Unknown"))
                tags_list.append(result.get("tags", ""))
                confidences.append(new_conf)
            else:
                verdicts.append(row.get("TI Verdict", "Unknown"))
                tags_list.append(row.get("TI Tags", ""))
                confidences.append(existing_conf)

        df["TI Verdict"]    = verdicts
        df["TI Tags"]       = tags_list
        df["TI Confidence"] = confidences

        mal  = (df["TI Verdict"] == "Malicious").sum()
        susp = (df["TI Verdict"] == "Suspicious").sum()
        log.info("Feed enrichment: %d malicious, %d suspicious", mal, susp)
        return df.sort_values("TI Confidence", ascending=False)


# Global feed manager instance
_feed_manager: FeedManager = None


def get_feed_manager(offline: bool = False) -> FeedManager:
    global _feed_manager
    if _feed_manager is None:
        _feed_manager = FeedManager()
        _feed_manager.load_all_feeds(offline=offline)
    return _feed_manager
