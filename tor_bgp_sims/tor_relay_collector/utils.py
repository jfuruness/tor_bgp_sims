from collections import Counter
from pprint import pprint

from frozendict import frozendict

from bgpy.simulation_engine import Policy
from roa_checker import ROAValidity

from .tor_relay import TORRelay
from .tor_relay_collector import TORRelayCollector

def get_tor_relay_groups(
    relays: tuple[TORRelay, ...] = TORRelayCollector().run()
) -> frozendict[Policy, tuple[TORRelay, ...]]:
    """Returns TOR relay groups"""

    return frozendict({
        GuardValid24: get_guard_valid_ipv4_len_24(relays),
        GuardValidNot24: get_guard_valid_ipv4_len_lt_24(relays),
        GuardNotValid24: get_guard_not_valid_ipv4_len_24(relays),
        GuardNotValidNot24: get_guard_not_valid_ipv4_len_lt_24(relays),
    })


def print_relay_stats(relays: tuple[TORRelay, ...]):
    versions = [x.version for x in relays]
    version_freq_dict = dict(Counter(versions))

    pprint(version_freq_dict)  # NOTE: not in order, in alphabetical order
    # All TOR versions in a bar graph

    guards = [x for x in relays if x.guard]
    # how many are guard
    print(f"Guard relays: {len(guards)}")
    # How many unique gaurd ASNs
    unique_asn_ipv4_gaurds = set([x.ipv4_origin for x in relays if x.guard])
    print(f"Guard relays with unique ipv4 ASNs: {len(unique_asn_ipv4_gaurds)}")
    # for ipv4:
    #   How many guard covered by ROA
    guard_ipv4_roa_covered = [
        x for x in relays if x.guard and not ROAValidity.is_unknown(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Guard covered by roa {len(guard_ipv4_roa_covered)}")
    #   How many guard covered by ROA and valid
    guard_ipv4_roa_valid = [
        x for x in relays if x.guard and ROAValidity.is_valid(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Guard valid by roa {len(guard_ipv4_roa_valid)}")
    #   How many guard covered by ROA and invalid
    guard_ipv4_roa_invalid = [
        x for x in relays if x.guard and ROAValidity.is_invalid(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Guard invalid by roa {len(guard_ipv4_roa_invalid)}")
    #   How many guard not covered by ROA
    guard_ipv4_roa_not_covered = [
        x for x in relays if x.guard and ROAValidity.is_unknown(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Guard not covered by roa {len(guard_ipv4_roa_not_covered)}")
    #   How many guard not covered by ROA and /24
    guard_ipv4_not_covered_and_shortest = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_unknown(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen == 24
        ):
            guard_ipv4_not_covered_and_shortest.append(x)
    print(
        "ipv4 Guard not covered by roa and /24 "
        f"{len(guard_ipv4_not_covered_and_shortest)}"
    )
    #   How many guard not covered by ROA and shorter than /24
    guard_ipv4_not_covered_and_not_shortest = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_unknown(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen != 24
        ):
            guard_ipv4_not_covered_and_not_shortest.append(x)
    print(
        "ipv4 Guard not covered by roa and not /24 "
        f"{len(guard_ipv4_not_covered_and_not_shortest)}"
    )
    # for ipv6:
    #   How many guard covered by ROA
    guard_ipv6_roa_covered = [
        x for x in relays if x.guard and not ROAValidity.is_unknown(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Guard covered by roa {len(guard_ipv6_roa_covered)}")
    #   How many guard covered by ROA and valid
    guard_ipv6_roa_valid = [
        x for x in relays if x.guard and ROAValidity.is_valid(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Guard valid by roa {len(guard_ipv6_roa_valid)}")
    #   How many guard covered by ROA and invalid
    guard_ipv6_roa_invalid = [
        x for x in relays if x.guard and ROAValidity.is_invalid(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Guard invalid by roa {len(guard_ipv6_roa_invalid)}")
    #   How many guard not covered by ROA
    guard_ipv6_roa_not_covered = [
        x
        for x in relays
        if x.guard and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix
    ]
    print(f"ipv6 Guard not covered by roa {len(guard_ipv6_roa_not_covered)}")
    #   How many guard not covered by ROA and /48
    guard_ipv6_not_covered_and_shortest = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_unknown(x.ipv6_roa_validity)
            and x.ipv6_prefix
            and x.ipv6_prefix.prefixlen == 48
        ):
            guard_ipv6_not_covered_and_shortest.append(x)
    print(
        "ipv6 Guard not covered by roa and /48 "
        f"{len(guard_ipv6_not_covered_and_shortest)}"
    )
    #   How many guard not covered by ROA and shorter than /48
    guard_ipv6_not_covered_and_not_shortest = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_unknown(x.ipv6_roa_validity)
            and x.ipv6_prefix
            and x.ipv6_prefix.prefixlen != 48
        ):
            guard_ipv6_not_covered_and_not_shortest.append(x)
    print(
        "ipv6 Guard not covered by roa and not /48 "
        f"{len(guard_ipv6_not_covered_and_not_shortest)}"
    )

    exits = [x for x in relays if x.exit]
    # how many are exit
    print(f"Exit relays: {len(exits)}")
    # How many unique exit ASNs
    unique_asn_ipv4_exits = set([x.ipv4_origin for x in relays if x.exit])
    print(f"Exit relays with unique ipv4 ASNs: {len(unique_asn_ipv4_exits)}")
    # for ipv4:
    #   How many exit covered by ROA
    exit_ipv4_roa_covered = [
        x for x in relays if x.exit and not ROAValidity.is_unknown(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Exit covered by roa {len(exit_ipv4_roa_covered)}")
    #   How many exit covered by ROA and valid
    exit_ipv4_roa_valid = [
        x for x in relays if x.exit and ROAValidity.is_valid(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Exit valid by roa {len(exit_ipv4_roa_valid)}")
    #   How many exit covered by ROA and invalid
    exit_ipv4_roa_invalid = [
        x for x in relays if x.exit and ROAValidity.is_invalid(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Exit invalid by roa {len(exit_ipv4_roa_invalid)}")
    #   How many exit not covered by ROA
    exit_ipv4_roa_not_covered = [
        x for x in relays if x.exit and ROAValidity.is_unknown(x.ipv4_roa_validity)
    ]
    print(f"ipv4 Exit not covered by roa {len(exit_ipv4_roa_not_covered)}")
    #   How many exit not covered by ROA and /24
    exit_ipv4_not_covered_and_shortest = list()
    for x in relays:
        if (
            x.exit
            and ROAValidity.is_unknown(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen == 24
        ):
            exit_ipv4_not_covered_and_shortest.append(x)
    print(
        "ipv4 Exit not covered by roa and /24 "
        f"{len(exit_ipv4_not_covered_and_shortest)}"
    )
    #   How many exit not covered by ROA and shorter than /24
    exit_ipv4_not_covered_and_not_shortest = list()
    for x in relays:
        if (
            x.exit
            and ROAValidity.is_unknown(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen != 24
        ):
            exit_ipv4_not_covered_and_not_shortest.append(x)
    print(
        "ipv4 Exit not covered by roa and not /24 "
        f"{len(exit_ipv4_not_covered_and_not_shortest)}"
    )
    # for ipv6:
    #   How many exit covered by ROA
    exit_ipv6_roa_covered = [
        x for x in relays if x.exit and not ROAValidity.is_unknown(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Exit covered by roa {len(exit_ipv6_roa_covered)}")
    #   How many exit covered by ROA and valid
    exit_ipv6_roa_valid = [
        x for x in relays if x.exit and ROAValidity.is_valid(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Exit valid by roa {len(exit_ipv6_roa_valid)}")
    #   How many exit covered by ROA and invalid
    exit_ipv6_roa_invalid = [
        x for x in relays if x.exit and ROAValidity.is_invalid(x.ipv6_roa_validity)
    ]
    print(f"ipv6 Exit invalid by roa {len(exit_ipv6_roa_invalid)}")
    #   How many exit not covered by ROA
    exit_ipv6_roa_not_covered = [
        x
        for x in relays
        if x.exit and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix
    ]
    print(f"ipv6 Exit not covered by roa {len(exit_ipv6_roa_not_covered)}")
    #   How many exit not covered by ROA and /48
    exit_ipv6_not_covered_and_shortest = list()
    for x in relays:
        if (
            x.exit
            and ROAValidity.is_unknown(x.ipv6_roa_validity)
            and x.ipv6_prefix
            and x.ipv6_prefix.prefixlen == 48
        ):
            exit_ipv6_not_covered_and_shortest.append(x)
    print(
        "ipv6 Exit not covered by roa and /48 "
        f"{len(exit_ipv6_not_covered_and_shortest)}"
    )
    #   How many exit not covered by ROA and shorter than /48
    exit_ipv6_not_covered_and_not_shortest = list()
    for x in relays:
        if (
            x.exit
            and ROAValidity.is_unknown(x.ipv6_roa_validity)
            and x.ipv6_prefix
            and x.ipv6_prefix.prefixlen != 48
        ):
            exit_ipv6_not_covered_and_not_shortest.append(x)
    print(
        "ipv6 Exit not covered by roa and not /48 "
        f"{len(exit_ipv6_not_covered_and_not_shortest)}"
    )


def get_guard_valid_ipv4_len_24(relays: tuple[TORRelay, ...]) -> tuple[TORRelay, ...]:
    """Returns guard relays valid by ROA with a /24 IPV4 prefix"""

    rv = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_valid(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen == 24
        ):
            rv.append(x)
    return tuple(rv)


def get_guard_valid_ipv4_len_lt_24(relays: tuple[TORRelay, ...]) -> tuple[TORRelay, ...]:
    """Returns guard relays valid by ROA with a < /24 IPV4 prefix"""

    rv = list()
    for x in relays:
        if (
            x.guard
            and ROAValidity.is_valid(x.ipv4_roa_validity)
            and x.ipv4_prefix.prefixlen < 24
        ):
            rv.append(x)
    return tuple(rv)


def get_guard_not_valid_ipv4_len_24(relays: tuple[TORRelay, ...]) -> tuple[TORRelay, ...]:
    """Returns guard relays not valid by ROA with a /24 IPV4 prefix"""

    rv = list()
    for x in relays:
        if (
            x.guard
            and (not ROAValidity.is_valid(x.ipv4_roa_validity))
            and x.ipv4_prefix.prefixlen == 24
        ):
            rv.append(x)
    return tuple(rv)


def get_guard_not_valid_ipv4_len_lt_24(relays: tuple[TORRelay, ...]) -> tuple[TORRelay, ...]:
    """Returns guard relays not valid by ROA with a < /24 IPV4 prefix"""

    rv = list()
    for x in relays:
        if (
            x.guard
            and (not ROAValidity.is_valid(x.ipv4_roa_validity))
            and x.ipv4_prefix.prefixlen < 24
        ):
            rv.append(x)
    return tuple(rv)
