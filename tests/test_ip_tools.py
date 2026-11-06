import pytest

from ip_tools import classify_ip


@pytest.mark.parametrize(
    "ip_text, expected_category",
    [
        ("8.8.8.8", "global"),
        ("10.0.0.5", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
    ],
)
def test_categories(ip_text, expected_category):
    assert classify_ip(ip_text)["category"] == expected_category


def test_global_has_no_explanation():
    assert classify_ip("8.8.8.8")["explanation"] is None


def test_non_global_has_explanation():
    assert classify_ip("10.0.0.5")["explanation"]


def test_whitespace_is_stripped():
    assert classify_ip("  8.8.8.8 \n")["ip"] == "8.8.8.8"


def test_garbage_raises_value_error():
    with pytest.raises(ValueError, match="not a valid IP"):
        classify_ip("not an ip")


def test_ipv6_is_rejected():
    with pytest.raises(ValueError, match="not supported"):
        classify_ip("2001:4860:4860::8888")
