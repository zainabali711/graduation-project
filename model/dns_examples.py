"""Curated DNS query examples for /dns-scan demos (from Daumel synthetic dataset)."""

from __future__ import annotations

# Six fixed examples: 2 benign, 2 ozymandns (strong LOOT), 1 cobaltstrike, 1 tcp_over_dns.
DNS_EXAMPLES: list[dict] = [
    {
        "id": "benign-xiaomi",
        "query": "api.account.xiaomi.com.",
        "expected_label": "Benign",
        "source_tool": "benign",
        "title": "Benign — short API host",
        "note": "Legitimate-looking short query from the benign set.",
    },
    {
        "id": "benign-typekit",
        "query": "use.typekit.net.",
        "expected_label": "Benign",
        "source_tool": "benign",
        "title": "Benign — CDN-style name",
        "note": "Common-style hostname from the benign set.",
    },
    {
        "id": "ozy-1",
        "query": "4006981-23400.id-36207.down.sshdns.ozymandns-txt.com.",
        "expected_label": "Malicious",
        "source_tool": "ozymandns",
        "title": "Malicious — ozymandns",
        "note": "Strong leave-one-tool-out recall (~0.996) for this tool family.",
    },
    {
        "id": "ozy-2",
        "query": "461-59742.id-57373.down.sshdns.ozymandns-txt.com.",
        "expected_label": "Malicious",
        "source_tool": "ozymandns",
        "title": "Malicious — ozymandns (alt)",
        "note": "Second ozymandns sample for demo coverage.",
    },
    {
        "id": "cs-1",
        "query": "www6.25275c1614b9.49670.dnsch.cobaltstrike-aaaa.com.",
        "expected_label": "Malicious",
        "source_tool": "cobaltstrike",
        "title": "Malicious — cobaltstrike",
        "note": "Moderate LOOT recall (~0.61); tool fingerprint still present.",
    },
    {
        "id": "tod-1",
        "query": "ba8Lb8C4gTcdOEGaKVMWZDduQRLFm.www.ggy666.tk.",
        "expected_label": "Malicious",
        "source_tool": "tcp_over_dns",
        "title": "Malicious — tcp_over_dns",
        "note": "Harder to generalize (LOOT malicious recall ~0.002 when tool held out).",
    },
]


def get_dns_examples() -> list[dict]:
    return list(DNS_EXAMPLES)
