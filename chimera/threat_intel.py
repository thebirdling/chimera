"""
Offline Threat Intelligence provider for Chimera.

Handles loading of local indicator lists (IPs, domains, hashes) to enrich
authentication events with known-bad reputation data.
"""

import csv
import logging
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)


class ThreatIntel:
    """
    Manages offline threat intelligence lists.
    
    Designed to work without external API calls. Loads indicators from
    local flat files (CSV/TXT).
    """

    def __init__(self, feed_path: Optional[str] = None):
        self.bad_ips: Set[str] = set()
        self.bad_asns: Set[str] = set()
        self.suspicious_countries: Set[str] = set()
        self._loaded = False
        
        if feed_path:
            self.load_feed(feed_path)

    def load_feed(self, path: str) -> None:
        """
        Load indicators from a file.
        
        Supports simple text files (one indicator per line) or CSVs.
        Auto-detects indicator type (IP, ASN, Country) based on format.
        """
        file_path = Path(path)
        if not file_path.exists():
            logger.warning(f"Threat feed not found: {path}")
            return

        count = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    # Basic heuristics for type detection
                    if line.startswith('AS') and line[2:].isdigit():
                        self.bad_asns.add(line)
                    elif len(line) == 2 and line.isalpha():
                        self.suspicious_countries.add(line.upper())
                    elif '.' in line or ':' in line:  # IPv4/IPv6
                        self.bad_ips.add(line)
                    
                    count += 1
            
            self._loaded = True
            logger.info(f"Loaded {count} indicators from {path}")
            
        except Exception as e:
            logger.error(f"Failed to load threat feed {path}: {e}")

    def check_ip(self, ip: str) -> float:
        """Return risk score (0.0-1.0) for an IP."""
        if ip in self.bad_ips:
            return 1.0
        return 0.0

    def check_asn(self, asn: str) -> float:
        """Return risk score (0.0-1.0) for an ASN."""
        if asn in self.bad_asns:
            return 1.0
        return 0.0

    def check_country(self, country: str) -> float:
        """Return risk score (0.0-1.0) for a country code."""
        if country in self.suspicious_countries:
            return 1.0
        return 0.0
