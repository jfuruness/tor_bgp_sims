
from datetime import date

from roa_checker import ROAChecker, ROAValidity, ROARouted

from tor_bgp_sims.tor_relay_collector import TORRelayCollector


relays = TORRelayCollector(dl_date=date(2024, 6, 5)).run()
relays = [x for x in relays if x.guard]


total_amount_covered = len([x for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN])
total_amount_not_covered = len([x for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN])
print("covered amount", str(total_amount_covered))
print("not covered amount", str(total_amount_not_covered))
total_amount_covered_24 = len([x for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen == 24])
total_amount_not_covered_24 = len([x for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen == 24])
print("covered amount /24", str(total_amount_covered_24))
print("not covered amount /24", str(total_amount_not_covered_24))
total_amount_covered_s24 = len([x for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen < 24])
total_amount_not_covered_s24 = len([x for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen < 24])
print("covered amount </24", str(total_amount_covered_s24))
print("not covered amount </24", str(total_amount_not_covered_s24))


total_weight = sum([x.bandwidth_weight for x in relays])
total_weight_covered = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN])
total_weight_not_covered = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN])
print("covered weight", str(total_weight_covered/total_weight))
print("not covered weight", str(total_weight_not_covered/total_weight))
total_weight_covered_24 = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen == 24])
total_weight_not_covered_24 = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen == 24])
print("covered weight /24", str(total_weight_covered_24/total_weight))
print("not covered weight /24", str(total_weight_not_covered_24/total_weight))
total_weight_covered_s24 = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is not ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen < 24])
total_weight_not_covered_s24 = sum([x.bandwidth_weight for x in relays if x.ipv4_roa_validity is ROAValidity.UNKNOWN and x.ipv4_prefix.prefixlen < 24])

print("covered weight </24", str(total_weight_covered_s24/total_weight))
print("not covered weight </24", str(total_weight_not_covered_s24/total_weight))
