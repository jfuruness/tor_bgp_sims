import sys
import os

# Add the directory containing the package to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Now you can import your modules
from tor_bgp_sims.tor_relay_collector.tor_relay_collector import TORRelayCollector
from tor_bgp_sims.tor_relay_collector.utils import print_relay_stats

relays = TORRelayCollector.run()
print_relay_stats(relays)
