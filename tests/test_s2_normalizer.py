"""S2 tests — normalizer: detection, defang/refang, validation."""
import pytest

from ioc_insight.normalizer import (
    InvalidIOCError,
    defang,
    detect_type,
    normalize,
    refang,
)


# --- type detection (plain input) ---

@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "ipv4"),
    ("185.220.101.47", "ipv4"),
    ("0.0.0.0", "ipv4"),
    ("255.255.255.255", "ipv4"),
    ("2001:4860:4860::8888", "ipv6"),
    ("::1", "ipv6"),
    ("fe80::1", "ipv6"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256"),
    ("google.com", "domain"),
    ("evil-login.top", "domain"),
    ("sub.domain.example.co.uk", "domain"),
    ("http://evil.com/path?q=1", "url"),
    ("https://phish.example.org/login", "url"),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


@pytest.mark.parametrize("bad", [
    "", "   ", "not an ioc!!", "999.999.999.999", "abc123",  # too short for md5
    "-invaliddomain.com", "domain-.com", "no spaces.com",
    "d41d8cd9",  # truncated hash
])
def test_detect_type_rejects_invalid(bad):
    with pytest.raises(InvalidIOCError):
        detect_type(bad)


# --- refang ---

@pytest.mark.parametrize("defanged,live", [
    ("hxxp://evil.com", "http://evil.com"),
    ("hxxps://evil.com/a", "https://evil.com/a"),
    ("HXXP://evil.com", "http://evil.com"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("evil(dot)com", "evil.com"),
    ("hxxps://evil-login[.]top/verify", "https://evil-login.top/verify"),
    ("185[.]220[.]101[.]47", "185.220.101.47"),
    ("user[at]example[.]com", "user@example.com"),
])
def test_refang(defanged, live):
    assert refang(defanged) == live


def test_defang_roundtrip():
    live = "https://evil.example.com/path"
    assert defang(live) == "hxxps://evil[.]example[.]com/path"
    assert refang(defang(live)) == live


# --- normalize (full pipeline) ---

def test_normalize_defanged_url():
    ioc = normalize("hxxps://evil-login[.]top/verify")
    assert ioc.type == "url"
    assert ioc.value == "https://evil-login.top/verify"
    assert ioc.raw == "hxxps://evil-login[.]top/verify"  # raw preserved


def test_normalize_defanged_ip():
    ioc = normalize("185[.]220[.]101[.]47")
    assert ioc.type == "ipv4"
    assert ioc.value == "185.220.101.47"


def test_normalize_hash_lowercased():
    ioc = normalize("D41D8CD98F00B204E9800998ECF8427E")
    assert ioc.type == "md5"
    assert ioc.value == "d41d8cd98f00b204e9800998ecf8427e"


def test_normalize_domain_lowercased_and_trailing_dot():
    ioc = normalize("EVIL[.]Example[.]COM.")
    assert ioc.type == "domain"
    assert ioc.value == "evil.example.com"


def test_normalize_strips_whitespace():
    ioc = normalize("  8.8.8.8  \n")
    assert ioc.value == "8.8.8.8"


def test_normalize_invalid_raises():
    with pytest.raises(InvalidIOCError):
        normalize("definitely not an ioc at all")
