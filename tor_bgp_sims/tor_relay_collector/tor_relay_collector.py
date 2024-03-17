from datetime import date, timedelta
from ipaddress import ip_network
from pathlib import Path
import pickle
from typing import Optional

import requests_cache
from tqdm import tqdm

from roa_collector import ROACollector
from roa_checker import ROAChecker

from .tor_relay import TORRelay


class TORRelayCollector:
    def __init__(
        self,
        requests_cache_db_path: Optional[Path] = None,
        dl_date: date | None = None,
    ) -> None:
        self.dl_date: date = dl_date if dl_date else date.today()
        # By default keep requests cached for a single day
        if requests_cache_db_path is None:
            requests_cache_db_path = Path.home() / f"tor_bgp_sims_{self.dl_date}.db"
        self.requests_cache_db_path: Path = requests_cache_db_path
        self.session = requests_cache.CachedSession(str(self.requests_cache_db_path))

    def __del__(self):
        self.session.close()

    def run(self) -> tuple[TORRelay, ...]:
        """Download TOR Relay data w/cached requests"""

        pickle_path = Path(str(self.requests_cache_db_path).replace(".db", ".pickle"))
        if not pickle_path.exists():
            data = self._parse_tor_relays()
            with pickle_path.open("wb") as f:
                pickle.dump(data, f)

        with pickle_path.open("rb") as f:
            return pickle.load(f)  # type: ignore

    def _parse_tor_relays(self) -> tuple[TORRelay, ...]:
        """Parses TOR relays from the consensus URL

        See TORRelay dataclass for docs on format
        """

        relevant_tor_lines: tuple[str, ...] = self._get_relevant_tor_lines()
        raw_tor_datas = self._get_raw_tor_data(relevant_tor_lines)
        init_vars = {"session": self.session, "roa_checker": self._init_roa_checker()}
        tor_relays = list()
        # NOTE: This takes about a half hour
        # but not going to bother multiprocessing this
        # due to rate limits and also caching - it only needs to run once
        for x in tqdm(raw_tor_datas, total=len(raw_tor_datas), desc="Parsing TOR"):
            tor_relays.append(TORRelay(**(x | init_vars)))
        return tuple(tor_relays)

    def _get_relevant_tor_lines(self) -> tuple[str, ...]:
        """Returns the relevant lines from TOR consensus"""

        try:
            resp = self.session.get(self._get_tor_relay_url())
            resp.raise_for_status()
        except Exception as e:
            print(e)
            print("Consensus not posted for current day, using previous")
            self.dl_date = self.dl_date - timedelta(days=1)
            resp = self.session.get(self._get_tor_relay_url())
            resp.raise_for_status()

        relevant_lines: list[str] = list()

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
            f"{self.dl_date.strftime('%Y-%m-%d-01-00-00')}-consensus"
        )

    def _get_raw_tor_data(
        self, relevant_lines: tuple[str, ...]
    ) -> tuple[dict[str, tuple[str, ...]], ...]:
        """Gets raw TOR data from relevant parsed lines"""

        raw_tor_data: list[dict[str, list[str]]] = list()
        for line in relevant_lines:
            sections = line.split()
            if sections[0] == "r":
                raw_tor_data.append(dict())
            try:
                raw_tor_data[-1][sections[0]] = sections[1:]
            except IndexError:
                print(sections)
                raise
        return tuple([{k: tuple(v) for k, v in x.items()} for x in raw_tor_data])

    def _init_roa_checker(self) -> ROAChecker:
        """Downloads ROAs and returns ROAChecker"""

        roa_checker = ROAChecker()
        # TODO: Change this to historical roas
        for roa in ROACollector(
            csv_path=None, requests_cache_db_path=self.requests_cache_db_path
        ).run():
            roa_checker.insert(ip_network(roa.prefix), roa.origin, roa.max_length)
        return roa_checker
