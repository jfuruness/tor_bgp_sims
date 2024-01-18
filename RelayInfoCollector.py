import requests # requests_cache
from dataclasses import dataclass


@dataclass(frozen=True)
class TorRelay:
    nickname: str
    fingerprint: str
    ipv4_address: str
    ipv6_address: str
    flags: tuple
    version: str
    bandwidth: int


def parse_consensus(consensus_data):
    lines = consensus_data.split('\n')

    relay_info_list = []

    nickname = None
    fingerprint = None
    ipv4_address = None
    ipv6_address = None
    flags = None
    version = None
    bandwidth = None

    for line in lines:
        parts = line.split()
        if not parts: continue 

        prefix = parts[0]

        # r seele AAoQ1DAR6kkoo19hBAX5K0QztNw FLHasPzfSj6HXHw/VDhAIKJhPdE 2024-01-11 12:53:30 104.53.221.159 9001 0
        if prefix == "r":
            if all((nickname, fingerprint, ipv4_address, flags, version, bandwidth)):
                relay_info_list.append(TorRelay(nickname, fingerprint, ipv4_address, ipv6_address, flags, version, bandwidth))

            nickname = parts[1]
            fingerprint = parts[2]
            ipv4_address = parts[6] 
            ipv6_address = None
            flags = None
            version = None
            bandwidth = None
        # a [2001:bc8:1860:607::1]:444
        elif prefix == "a":
            ipv6_address = parts[1]
        # s Fast Running Stable V2Dir Valid
        elif prefix == "s":
            flags = tuple(parts[1:])
        # v Tor 0.4.8.9
        elif prefix == "v":
            version = parts[2]
        # w Bandwidth=520
        elif prefix == "w":
            bandwidth = parts[1][10:]

    if all((nickname, fingerprint, ipv4_address, flags, version, bandwidth)):
        relay_info_list.append(TorRelay(nickname, fingerprint, ipv4_address, ipv6_address, flags, version, bandwidth))

    return relay_info_list

if __name__ == '__main__':
    consensus_url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/2024-01-15-19-00-00-consensus'
    response = requests.get(consensus_url)
    consensus_data = response.text

    if consensus_data is None: raise SystemExit("Failed to load consensus data.")

    relay_info_list = parse_consensus(consensus_data)

    
    # for relay_info in relay_info_list:
    #     print(f"Nickname: {relay_info.nickname}")
    #     print(f"Fingerprint: {relay_info.fingerprint}")
    #     print(f"IPv4 Address: {relay_info.ipv4_address}")
    #     print(f"IPv6 Address: {relay_info.ipv6_address}")
    #     print(f"Flags: {relay_info.flags}")
    #     print(f"Version Number: {relay_info.version}")
    #     print(f"Bandwidth: {relay_info.bandwidth}")
    #     print("\n")