from dataclasses import dataclass, InitVar
from ipaddress import ip_network, IPv4Network, IPv6Network
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
    asns: tuple[int, ...] = ()
    ipv4_roa_validity: Optional[ROAValidity] = None
    ipv4_roa_routed: Optional[ROARouted] = None
    ipv6_roa_validity: Optional[ROAValidity] = None
    ipv6_roa_routed: Optional[ROARouted] = None
    session: InitVar[CachedSession]
    roa_checker: InitVar[ROAChecker]

    def __post_init__(
        self,
        session: CachedSession,
        ROAChecker: ROAChecker,
    ) -> None:
        """Gets ASNs and ROAs for TOR relay"""

        raise NotImplementedError("Store ASNs, assert only 1")
        # Make sure ASNs are from both IPV4 and IPv6
        raise NotImplementedError("Store ROA validities and routed")

    @property
    def ipv4_addr(self) -> IPv4Network:
        """Returns IPv4 prefix"""

        raise NotImplementedError

    @property
    def ipv6_addr(self) -> IPv6Network:
        """Returns IPv6 prefix"""

        raise NotImplementedError

    @property
    def gaurd_relay(self) -> bool:
        """Returns True if eligible to be a gaurd node"""

        raise NotImplementedError

    @property
    def exit_relay(self) -> bool:
        """Returns True if eligible to be an exit node"""

        raise NotImplementedError

    @property
    def version(self) -> str:
        """Returns the Relay version"""

        raise NotImplementedError

    @staticmethod
    def get_asns(session: CachedSession, ip_addr: IPv4Network | IPv6Network) -> tuple[int, ...]:
        """Returns ASNs using RIPE from a given IP addr"""


        # api_endpoint = f"https://stat.ripe.net/data/related-prefixes/data.json?data_overload_limit=ignore&resource={ip_address}"
        raise NotImplementedError("Get ASNs")
        raise NotImplementedError("Assert ASNs exist")
        raise NotImplementedError("Return ASNs as tuple of ints")
