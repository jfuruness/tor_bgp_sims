from collections import Counter

from roa_checker import ROAValidity

from .tor_relay_collector import TORRelayCollector

def main():
    relays = TORRelayCollector().run()
    print("GET STATISTICS ON THESE HERE, MAKE GRAPHS!!!")
    versions = [x.version for x in relays]
    version_freq_dict = dict(Counter(versions))
    from pprint import pprint
    pprint(version_freq_dict)  # NOTE: not in order, in alphabetical order
    # All TOR versions in a bar graph

    guards = [x for x in relays if x.guard]
    # how many are guard
    print(f"Guard relays: {len(guards)}")
    # for ipv4:
    #   How many guard covered by ROA
    guard_ipv4_roa_covered = [x for x in relays if x.guard and not ROAValidity.is_unknown(x.ipv4_roa_validity)]
    print(f"ipv4 Guard covered by roa {len(guard_ipv4_roa_covered)}")
    #   How many guard covered by ROA and valid
    guard_ipv4_roa_valid = [x for x in relays if x.guard and ROAValidity.is_valid(x.ipv4_roa_validity)]
    print(f"ipv4 Guard valid by roa {len(guard_ipv4_roa_valid)}")
    #   How many guard covered by ROA and invalid
    guard_ipv4_roa_invalid = [x for x in relays if x.guard and ROAValidity.is_invalid(x.ipv4_roa_validity)]
    print(f"ipv4 Guard invalid by roa {len(guard_ipv4_roa_invalid)}")
    #   How many guard not covered by ROA
    guard_ipv4_roa_not_covered = [x for x in relays if x.guard and ROAValidity.is_unknown(x.ipv4_roa_validity)]
    print(f"ipv4 Guard not covered by roa {len(guard_ipv4_roa_not_covered)}")
    #   How many guard not covered by ROA and /24
    guard_ipv4_not_covered_and_shortest = list()
    for x in relays:
        if x.guard and ROAValidity.is_unknown(x.ipv4_roa_validity) and x.ipv4_prefix.prefixlen == 24:
            guard_ipv4_not_covered_and_shortest.append(x)
    print(f"ipv4 Guard not covered by roa and /24 {len(guard_ipv4_not_covered_and_shortest)}")
    #   How many guard not covered by ROA and shorter than /24
    guard_ipv4_not_covered_and_not_shortest = list()
    for x in relays:
        if x.guard and ROAValidity.is_unknown(x.ipv4_roa_validity) and x.ipv4_prefix.prefixlen != 24:
            guard_ipv4_not_covered_and_not_shortest.append(x)
    print(f"ipv4 Guard not covered by roa and not /24 {len(guard_ipv4_not_covered_and_not_shortest)}")
    # for ipv6:
    #   How many guard covered by ROA
    guard_ipv6_roa_covered = [x for x in relays if x.guard and not ROAValidity.is_unknown(x.ipv6_roa_validity)]
    print(f"ipv6 Guard covered by roa {len(guard_ipv6_roa_covered)}")
    #   How many guard covered by ROA and valid
    guard_ipv6_roa_valid = [x for x in relays if x.guard and ROAValidity.is_valid(x.ipv6_roa_validity)]
    print(f"ipv6 Guard valid by roa {len(guard_ipv6_roa_valid)}")
    #   How many guard covered by ROA and invalid
    guard_ipv6_roa_invalid = [x for x in relays if x.guard and ROAValidity.is_invalid(x.ipv6_roa_validity)]
    print(f"ipv6 Guard invalid by roa {len(guard_ipv6_roa_invalid)}")
    #   How many guard not covered by ROA
    guard_ipv6_roa_not_covered = [x for x in relays if x.guard and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix]
    print(f"ipv6 Guard not covered by roa {len(guard_ipv6_roa_not_covered)}")
    #   How many guard not covered by ROA and /48
    guard_ipv6_not_covered_and_shortest = list()
    for x in relays:
        if x.guard and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix and x.ipv6_prefix.prefixlen == 48:
            guard_ipv6_not_covered_and_shortest.append(x)
    print(f"ipv6 Guard not covered by roa and /48 {len(guard_ipv6_not_covered_and_shortest)}")
    #   How many guard not covered by ROA and shorter than /48
    guard_ipv6_not_covered_and_not_shortest = list()
    for x in relays:
        if x.guard and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix and x.ipv6_prefix.prefixlen != 48:
            guard_ipv6_not_covered_and_not_shortest.append(x)
    print(f"ipv6 Guard not covered by roa and not /48 {len(guard_ipv6_not_covered_and_not_shortest)}")




    exits = [x for x in relays if x.exit]
    # how many are exit
    print(f"Exit relays: {len(exits)}")
    # for ipv4:
    #   How many exit covered by ROA
    exit_ipv4_roa_covered = [x for x in relays if x.exit and not ROAValidity.is_unknown(x.ipv4_roa_validity)]
    print(f"ipv4 Exit covered by roa {len(exit_ipv4_roa_covered)}")
    #   How many exit covered by ROA and valid
    exit_ipv4_roa_valid = [x for x in relays if x.exit and ROAValidity.is_valid(x.ipv4_roa_validity)]
    print(f"ipv4 Exit valid by roa {len(exit_ipv4_roa_valid)}")
    #   How many exit covered by ROA and invalid
    exit_ipv4_roa_invalid = [x for x in relays if x.exit and ROAValidity.is_invalid(x.ipv4_roa_validity)]
    print(f"ipv4 Exit invalid by roa {len(exit_ipv4_roa_invalid)}")
    #   How many exit not covered by ROA
    exit_ipv4_roa_not_covered = [x for x in relays if x.exit and ROAValidity.is_unknown(x.ipv4_roa_validity)]
    print(f"ipv4 Exit not covered by roa {len(exit_ipv4_roa_not_covered)}")
    #   How many exit not covered by ROA and /24
    exit_ipv4_not_covered_and_shortest = list()
    for x in relays:
        if x.exit and ROAValidity.is_unknown(x.ipv4_roa_validity) and x.ipv4_prefix.prefixlen == 24:
            exit_ipv4_not_covered_and_shortest.append(x)
    print(f"ipv4 Exit not covered by roa and /24 {len(exit_ipv4_not_covered_and_shortest)}")
    #   How many exit not covered by ROA and shorter than /24
    exit_ipv4_not_covered_and_not_shortest = list()
    for x in relays:
        if x.exit and ROAValidity.is_unknown(x.ipv4_roa_validity) and x.ipv4_prefix.prefixlen != 24:
            exit_ipv4_not_covered_and_not_shortest.append(x)
    print(f"ipv4 Exit not covered by roa and not /24 {len(exit_ipv4_not_covered_and_not_shortest)}")
    # for ipv6:
    #   How many exit covered by ROA
    exit_ipv6_roa_covered = [x for x in relays if x.exit and not ROAValidity.is_unknown(x.ipv6_roa_validity)]
    print(f"ipv6 Exit covered by roa {len(exit_ipv6_roa_covered)}")
    #   How many exit covered by ROA and valid
    exit_ipv6_roa_valid = [x for x in relays if x.exit and ROAValidity.is_valid(x.ipv6_roa_validity)]
    print(f"ipv6 Exit valid by roa {len(exit_ipv6_roa_valid)}")
    #   How many exit covered by ROA and invalid
    exit_ipv6_roa_invalid = [x for x in relays if x.exit and ROAValidity.is_invalid(x.ipv6_roa_validity)]
    print(f"ipv6 Exit invalid by roa {len(exit_ipv6_roa_invalid)}")
    #   How many exit not covered by ROA
    exit_ipv6_roa_not_covered = [x for x in relays if x.exit and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix]
    print(f"ipv6 Exit not covered by roa {len(exit_ipv6_roa_not_covered)}")
    #   How many exit not covered by ROA and /48
    exit_ipv6_not_covered_and_shortest = list()
    for x in relays:
        if x.exit and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix and x.ipv6_prefix.prefixlen == 48:
            exit_ipv6_not_covered_and_shortest.append(x)
    print(f"ipv6 Exit not covered by roa and /48 {len(exit_ipv6_not_covered_and_shortest)}")
    #   How many exit not covered by ROA and shorter than /48
    exit_ipv6_not_covered_and_not_shortest = list()
    for x in relays:
        if x.exit and ROAValidity.is_unknown(x.ipv6_roa_validity) and x.ipv6_prefix and x.ipv6_prefix.prefixlen != 48:
            exit_ipv6_not_covered_and_not_shortest.append(x)
    print(f"ipv6 Exit not covered by roa and not /48 {len(exit_ipv6_not_covered_and_not_shortest)}")


if __name__ == "__main__":
    main()
