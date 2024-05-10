import sys
import os
import pickle

# https://stackoverflow.com/questions/16981921/relative-imports-in-python-3
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from tor_bgp_sims.tor_relay_collector import TORRelayCollector, TORRelay
from tor_bgp_sims.tor_relay_collector.utils import *


def get_penalty_matrix(
    relays: tuple[TORRelay, ...] = TORRelayCollector().run()
):
    penalty_matrix = dict(dict())
    
    guard_valid_24 = get_guard_valid_ipv4_len_24(relays)
    guard_valid_lt_24 = get_guard_valid_ipv4_len_lt_24(relays)
    guard_not_valid_24 = get_guard_not_valid_ipv4_len_24(relays)
    guard_not_valid_lt_24 = get_guard_not_valid_ipv4_len_lt_24(relays)

    populate_matrix(guard_valid_24, 1, penalty_matrix)
    populate_matrix(guard_valid_lt_24, 0.42, penalty_matrix)
    populate_matrix(guard_not_valid_24, 0.25, penalty_matrix)
    populate_matrix(guard_not_valid_lt_24, 0.17, penalty_matrix)

    with open('penalty_matrix.pickle', 'wb') as f:
        pickle.dump(penalty_matrix, f)

    # return penalty_matrix

def populate_matrix(relays, weight, matrix):
    for x in relays:
        asn = x.ipv4_origin
        fp = x.r[1]

        if asn not in matrix:
            matrix[asn] = {}

        matrix[asn][fp] = weight


# if __name__ == '__main__':
#     get_penalty_matrix()