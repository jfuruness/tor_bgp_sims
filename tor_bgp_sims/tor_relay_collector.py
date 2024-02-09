from datetime import date
from ipaddress import ip_network
from pathlib import Path
from typing import Optional

import requests_cache

from roa_collector import ROACollector
from roa_checker import ROAChecker

from .tor_relay import TORRelay


class TORRelayCollector:
    def __init__(
        self,
        requests_cache_db_path: Optional[Path] = None,
    ):
        # By default keep requests cached for a single day
        if requests_cache_db_path is None:
            requests_cache_db_path = Path("/tmp/") / f"{date.today()}.db"
        self.requests_cache_db_path: Path = requests_cache_db_path
        self.session = requests_cache.CachedSession(str(self.requests_cache_db_path))

    def __del__(self):
        self.session.close()

    def run(self) -> None:
        """Download TOR Relay data w/cached requests"""

        relays = self._parse_tor_relays()
        for relay in relays:
            print(relay)
            input()

    def _parse_tor_relays(self) -> tuple[TORRelay, ...]:
        """Parses TOR relays from the consensus URL

        See TORRelay dataclass for docs on format
        """

        relevant_tor_lines: tuple[str, ...] = self._get_relevant_tor_lines()
        raw_tor_data = self._get_raw_tor_data(relevant_tor_lines)
        init_vars = {"session": self.session, "roa_checker": ROAChecker()}
        return tuple([TORRelay(**(x | init_vars)) for x in raw_tor_data])

    def _get_relevant_tor_lines(self) -> tuple[str, ...]:
        """Returns the relevant lines from TOR consensus"""

        resp = self.session.get(self._get_tor_relay_url())
        resp.raise_for_status()

        relevant_lines = list()

        relevant_line = False
        for line in resp.text.split("\n"):
            if line.startswith("r "):
                relevant_line = True
            elif line.startswith("directory-footer"):
                assert relevant_lines, "Didn't parse any TOR lines"
                return tuple(relevant_lines)
            if relevant_line:
                relevant_lines.append(line)
        raise NotImplementedError("Never reached directory footer")

    def _get_tor_relay_url(self) -> str:
        """Returns TOR relay URL with todays date. Old dates aren't saved here"""

        return (
            "https://collector.torproject.org/recent/relay-descriptors/consensuses/"
            f"{date.today().strftime('%Y-%m-%d-01-00-00')}-consensus"
        )

    def _get_raw_tor_data(
        self,
        relevant_lines: tuple[str, ...]
    ) -> tuple[dict[str, tuple], ...]:
        """Gets raw TOR data from relevant parsed lines"""

        raw_tor_data = list()
        for line in relevant_lines:
            sections = line.split()
            if sections[0] == "r":
                raw_tor_data.append(dict())
            try:
                raw_tor_data[-1][sections[0]] = sections[1:]
            except IndexError:
                print(sections)
                raise
        return raw_tor_data

    def _init_roa_checker(self) -> ROAChecker:
        """Downloads ROAs and returns ROAChecker"""

        roa_checker = ROAChecker()
        # TODO: Change this to historical roas
        for roa in ROACollector(csv_path=None).run():
            roa_checker.insert(ip_network(roa.prefix), roa.origin, roa.max_length)
        return roa_checker
