from dataclasses import dataclass, InitVar
from ipaddress import ip_network, IPv4Network, IPv6Network
from pprint import pprint, pformat
from typing import Optional

from requests_cache import CachedSession

from roa_checker import ROAChecker, ROAValidity, ROARouted


@dataclass(frozen=True, slots=True)
class TORRelay:
    """Stores data on TOR relays

    Super weird format, just check the URL
    https://spec.torproject.org/dir-spec/consensus-formats.html


    r contains IP address:
        ex: r seele AtNw etVuH1 2024-02-07 07:01:56 104.53.221.159 9001 0
    a contains IPv6 address
        ex: a [2001:41d0:404:300::dd2]:9001
    s contains flags:
        ex: s Fast HSDir Running Stable V2Dir Valid
    v contains version:
        ex: v Tor 0.4.8.10
    pr is proto family
        ex: pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2
        HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3
        Microdesc=1-2 Padding=2 Relay=1-4
    w contains bandwidth
        ex: w Bandwidth=630
    p is port list
        ex: p reject 1-65535

    As far as the possible flags (from URL above):
      "Authority" if the router is a directory authority.
      "BadExit" if the router is believed to be useless as an exit node
         (because its ISP censors it, because it is behind a restrictive
         proxy, or for some similar reason).
      "Exit" if the router is more useful for building
         general-purpose exit circuits than for relay circuits.  The
         path building algorithm uses this flag; see path-spec.txt.
      "Fast" if the router is suitable for high-bandwidth circuits.
      "Guard" if the router is suitable for use as an entry guard.
      "HSDir" if the router is considered a v2 hidden service directory.
      "MiddleOnly" if the router is considered unsuitable for
         usage other than as a middle relay. Clients do not need
         to handle this option, since when it is present, the authorities
         will automatically vote against flags that would make the router
         usable in other positions. (Since 0.4.7.2-alpha.)
      "NoEdConsensus" if any Ed25519 key in the router's descriptor or
         microdescriptor does not reflect authority consensus.
      "Stable" if the router is suitable for long-lived circuits.
      "StaleDesc" if the router should upload a new descriptor because
         the old one is too old.
      "Running" if the router is currently usable over all its published
         ORPorts. (Authorities ignore IPv6 ORPorts unless configured to
         check IPv6 reachability.) Relays without this flag are omitted
         from the consensus, and current clients (since 0.2.9.4-alpha)
         assume that every listed relay has this flag.
      "Valid" if the router has been 'validated'. Clients before
         0.2.9.4-alpha would not use routers without this flag by
         default. Currently, relays without this flag are omitted
         from the consensus, and current (post-0.2.9.4-alpha) clients
         assume that every listed relay has this flag.
      "V2Dir" if the router implements the v2 directory protocol or
         higher.
    """

    r: tuple[str, ...]
    s: tuple[str, ...]
    v: tuple[str, ...]
    pr: tuple[str, ...]
    w: tuple[str, ...]
    p: tuple[str, ...]
    session: InitVar[CachedSession]
    roa_checker: InitVar[ROAChecker]
    a: tuple[str, ...] = ()
    ipv4_prefix: Optional[IPv4Network] = None
    ipv4_origin: Optional[int] = None
    ipv4_roa_validity: Optional[ROAValidity] = None
    ipv4_roa_routed: Optional[ROARouted] = None
    ipv6_prefix: Optional[IPv4Network] = None
    ipv6_origin: Optional[int] = None
    ipv6_roa_validity: Optional[ROAValidity] = None
    ipv6_roa_routed: Optional[ROARouted] = None

    def __post_init__(
        self,
        session: CachedSession,
        roa_checker: ROAChecker,
    ) -> None:
        """Gets ASNs and ROAs for TOR relay"""

        # Get ipv4 prefix origin pair
        ipv4_prefix, ipv4_origin = self.get_prefix_origin_pair(session, self.ipv4_addr)
        object.__setattr__(self, "ipv4_prefix", ipv4_prefix)
        object.__setattr__(self, "ipv4_origin", ipv4_origin)

        # get ipv4 roa validity and routed
        ipv4_validity, ipv4_routed = roa_checker.get_validity(ipv4_prefix, ipv4_origin)
        object.__setattr__(self, "ipv4_roa_validity", ipv4_validity)
        object.__setattr__(self, "ipv4_roa_routed", ipv4_routed)

        # Get ipv6 prefix origin pair
        if self.ipv6_addr:
            ipv6_prefix, ipv6_origin = self.get_prefix_origin_pair(
                session, self.ipv6_addr
            )
            object.__setattr__(self, "ipv6_prefix", ipv6_prefix)
            object.__setattr__(self, "ipv6_origin", ipv6_origin)

            # get ipv6 roa validity and routed
            ipv6_validity, ipv6_routed = roa_checker.get_validity(
                ipv6_prefix, ipv6_origin
            )
            object.__setattr__(self, "ipv6_roa_validity", ipv6_validity)
            object.__setattr__(self, "ipv6_roa_routed", ipv6_routed)
        else:
            object.__setattr__(self, "ipv6_roa_validity", ROAValidity.UNKNOWN)
            object.__setattr__(self, "ipv6_roa_routed", ROARouted.UNKNOWN)

        # assert not self.ipv6_addr or ipv4_origin == ipv6_origin

    @property
    def ipv4_addr(self) -> IPv4Network:
        """Returns IPv4 prefix

        ex: r seele AtNw etVuH1 2024-02-07 07:01:56 104.53.221.159 9001 0
        """

        return ip_network(self.r[5])

    @property
    def ipv6_addr(self) -> Optional[IPv6Network]:
        """Returns IPv6 prefix"""

        if self.a:
            return ip_network(self.a[0].split("]")[0][1:])

    @property
    def guard(self) -> bool:
        return self.guard_relay

    @property
    def guard_relay(self) -> bool:
        """Returns True if eligible to be a guard node"""

        return "Guard" in self.s

    @property
    def exit(self) -> bool:
        return self.exit_relay

    @property
    def exit_relay(self) -> bool:
        """Returns True if eligible to be an exit node"""

        return "Exit" in self.s and "BadExit" not in self.s

    @property
    def version(self) -> str:
        """Returns the Relay version"""

        return self.v[1]

    @staticmethod
    def get_prefix_origin_pair(
        session: CachedSession, ip_addr: IPv4Network | IPv6Network, debug: bool = False
    ) -> tuple[IPv4Network | IPv6Network, int]:
        """Returns ASNs and prefixesusing RIPE from a given IP addr"""

        URL = "https://stat.ripe.net/data/related-prefixes/data.json"
        params = {"data_overload_limit": "ignore", "resource": str(ip_addr)}
        resp = session.get(URL, params=params)
        resp.raise_for_status()
        data = resp.json()
        if debug:
            pprint(data)
            input()

        prefix_origin_pairs = list()
        for inner in data["data"]["prefixes"]:
            # Sometimes API returns prefixes that don't overlap...
            if ip_network(inner["prefix"]).overlaps(ip_addr):
                prefix_origin_pairs.append(
                    (ip_network(inner["prefix"]), int(inner["origin_asn"]))
                )
        assert prefix_origin_pairs, f"No prefixes found for {ip_addr}"

        # Ensure that the second most isn't the same length...
        pairs = sorted(prefix_origin_pairs, key=lambda x: x[0].prefixlen)

        if len(pairs) > 1 and pairs[-1][0].prefixlen == pairs[-2][0].prefixlen:
            msg = f"for {ip_addr}, need both: {pformat(resp.json(), indent=4)}"
            print(msg)

        resp.close()
        # Get most specific prefix origin paid
        return pairs[-1]
