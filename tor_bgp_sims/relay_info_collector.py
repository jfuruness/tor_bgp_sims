import requests # requests_cache
import requests_cache
from dataclasses import dataclass


@dataclass
class TorRelay:
    nickname: str
    fingerprint: str
    ipv4_address: str
    ipv6_address: str
    flags: tuple
    version: str
    bandwidth: int

    prefixes: set
    asns: set


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
    prefixes = None
    asns = None

    for line in lines:
        parts = line.split()
        if not parts: continue

        prefix = parts[0]

        # r seele AAoQ1DAR6kkoo19hBAX5K0QztNw FLHasPzfSj6HXHw/VDhAIKJhPdE 2024-01-11 12:53:30 104.53.221.159 9001 0
        if prefix == "r":
            if all((nickname, fingerprint, ipv4_address, flags, version, bandwidth)):
                relay_info_list.append(TorRelay(nickname, fingerprint, ipv4_address, ipv6_address, flags, version, bandwidth, prefixes, asns))

            nickname = parts[1]
            fingerprint = parts[2]
            ipv4_address = parts[6]
            prefixes, asns = get_ripe_info(ipv4_address)
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
        relay_info_list.append(TorRelay(nickname, fingerprint, ipv4_address, ipv6_address, flags, version, bandwidth, prefixes, asns))

    return relay_info_list


def get_ripe_info(ip_address):
    try:
        api_endpoint = f"https://stat.ripe.net/data/related-prefixes/data.json?data_overload_limit=ignore&resource={ip_address}"
        response = requests.get(api_endpoint)
        data = response.json()
        prefixes_data = data.get('data', {}).get('prefixes', {})
        prefixes = set(entry['prefix'] for entry in prefixes_data)
        asns = set(entry['origin_asn'] for entry in prefixes_data)
        return prefixes, asns
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch RIPE Stat data for {ip_address}. Error: {e}")
        return [], []


if __name__ == '__main__':

    consensus_url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/2024-01-24-01-00-00-consensus'
    response = requests.get(consensus_url)
    consensus_data = response.text

    if response.status_code != 200:
        raise SystemExit(f"Failed to load consensus data. Status code: {response.status_code}")

    requests_cache.install_cache('ripe_stat_cache')
    relay_info_list = parse_consensus(consensus_data)

    # for relay_info in relay_info_list:
    #     print(f"Nickname: {relay_info.nickname}")
    #     print(f"Fingerprint: {relay_info.fingerprint}")
    #     print(f"IPv4 Address: {relay_info.ipv4_address}")
    #     print(f"IPv6 Address: {relay_info.ipv6_address}")
    #     print(f"Flags: {relay_info.flags}")
    #     print(f"Version Number: {relay_info.version}")
    #     print(f"Bandwidth: {relay_info.bandwidth}")
    #     print(f"Prefixes: {relay_info.prefixes}")
    #     print(f"ASNs: {relay_info.asns}")
    #     print("\n")
