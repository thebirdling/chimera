
import pytest
from chimera.threat_intel import ThreatIntel

def test_threat_intel_load(tmp_path):
    # Create dummy feed
    feed_file = tmp_path / "threats.txt"
    feed_file.write_text("""
    # Comments should be ignored
    192.168.1.100
    10.0.0.5
    AS13335
    XX
    """)
    
    ti = ThreatIntel(feed_path=str(feed_file))
    
    assert ti.check_ip("192.168.1.100") == 1.0
    assert ti.check_ip("8.8.8.8") == 0.0
    
    assert ti.check_asn("AS13335") == 1.0
    assert ti.check_asn("AS12345") == 0.0
    
    assert ti.check_country("XX") == 1.0
    assert ti.check_country("US") == 0.0

def test_threat_intel_empty():
    ti = ThreatIntel()
    assert ti.check_ip("1.1.1.1") == 0.0
