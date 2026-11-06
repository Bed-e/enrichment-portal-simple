import ipaddress

# Fixed explanation for each non-global category.
EXPLANATIONS = {
    "private": "Not routable on the public internet, so public sources have no data on it. "
    "Check internal tools such as DHCP logs and asset inventory.",
    "loopback": "This address points back at the machine itself (localhost). It is never a remote host.",
    "link_local": "Self-assigned address used only on the local network segment, usually when DHCP failed.",
    "multicast": "Used to send to a group of hosts at once, not to a single machine.",
    "reserved": "Set aside for special use by the internet standards, so it is not a normal public host.",
    "other_non_global": "Not a public internet address, so public sources have no data on it.",
}


def classify_ip(ip_text):
    """Return {"ip", "category", "explanation"}. Raises ValueError with a message for the page."""
    try:
        ip = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        raise ValueError("That is not a valid IP address.")

    if ip.version == 6:
        raise ValueError("IPv6 is not supported yet.")

    # Order matters: Python counts loopback and link-local as "private" too,
    # and 240.0.0.0/4 as both reserved and private, so check the specific ones first.
    if ip.is_loopback:
        category = "loopback"
    elif ip.is_link_local:
        category = "link_local"
    elif ip.is_multicast:
        category = "multicast"
    elif ip.is_reserved:
        category = "reserved"
    elif ip.is_private:
        category = "private"
    elif ip.is_global:
        category = "global"
    else:
        category = "other_non_global"

    return {
        "ip": str(ip),
        "category": category,
        "explanation": EXPLANATIONS.get(category),  # None for "global"
    }
