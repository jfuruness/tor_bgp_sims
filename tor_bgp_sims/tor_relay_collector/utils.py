from frozendict import frozendict

from .tor_relay import TORRelay
from .tor_relay_collector import TORRelayCollector


def get_tor_relay_ipv4_origin_guard_dict() -> frozendict[int, tuple[TORRelay, ...]]:
    """Gets IPv4 TOR Relay information"""

    relays = TORRelayCollector().run()
    data = dict()
    for relay in relays:
        ipv4_origin = relay.ipv4_origin
        if ipv4_origin not in data:
            data[ipv4_origin] = list()
        data[ipv4_origin].append(relay)

    return frozendict({k: tuple(v) for k, v in data.items()})
