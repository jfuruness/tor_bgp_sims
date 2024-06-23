import numpy as np
import string

from tor_bgp_sims.tor_relay_collector import TORRelayCollector, TORRelay
from tor_bgp_sims.tor_relay_collector.utils import *

relays: tuple[TORRelay, ...] = TORRelayCollector().run()

guard_valid_24 = get_guard_valid_ipv4_len_24(relays)
guard_valid_lt_24 = get_guard_valid_ipv4_len_lt_24(relays)
guard_not_valid_24 = get_guard_not_valid_ipv4_len_24(relays)
guard_not_valid_lt_24 = get_guard_not_valid_ipv4_len_lt_24(relays)

all_guards = guard_valid_24 + guard_valid_lt_24 + guard_not_valid_24 + guard_not_valid_lt_24
safer_guards = guard_valid_24 + guard_valid_lt_24 + guard_not_valid_24

all_weights = []
for g in all_guards:
    all_weights.append(int(g.w[0].strip(string.ascii_letters + '=')))
sum_weights = np.sum(all_weights)

safer_weights = []
for g in safer_guards:
    safer_weights.append(int(g.w[0].strip(string.ascii_letters + '=')))

sum_safer_weights = np.sum(safer_weights)

print()
print('Fraction of bandwidth remaining:', sum_safer_weights / sum_weights)

probs = [w / sum_weights for w in all_weights]
all_entropy = 0
for i in probs:
    all_entropy += i*np.log2(i)
all_entropy *= -1

print('Entropy before excluding unsafe guards:', all_entropy)

probs = [w / sum_safer_weights for w in safer_weights]
safer_entropy = 0
for i in probs:
    safer_entropy += i*np.log2(i)
safer_entropy *= -1

print('Entropy after excluding unsafe guards:', safer_entropy)

print('Percent reduction in entropy:', 100 * (1 - (safer_entropy / all_entropy)))
