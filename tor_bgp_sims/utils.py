import json
from pathlib import Path
import random
import os
from typing import Optional

from frozendict import frozendict

from bgpy.as_graphs import CAIDAASGraphConstructor
from bgpy.simulation_engine import ROVSimplePolicy
from bgpy.simulation_framework.utils import get_country_asns

from rov_collector import rov_collector_classes


class RealROVSimplePolicy(ROVSimplePolicy):
    name = "RealROV"


def get_real_world_rov_asn_cls_dict(
    json_path: Path = Path.home() / "Desktop" / "rov_info.json",
    requests_cache_db_path: Optional[Path] = None,
) -> frozendict[int, type[RealROVSimplePolicy]]:
    if not json_path.exists():
        for CollectorCls in rov_collector_classes:
            CollectorCls(
                json_path=json_path,
                requests_cache_db_path=requests_cache_db_path,
            ).run()  # type: ignore

    python_hash_seed = os.environ.get("PYTHONHASHSEED")
    if python_hash_seed:
        random.seed(int(python_hash_seed))

    with json_path.open() as f:
        data = json.load(f)
        hardcoded_dict = dict()
        for asn, info_list in data.items():
            max_percent: float = 0
            # Calculate max_percent for each ASN
            for info in info_list:
                max_percent = max(max_percent, float(info["percent"]))

            # Use max_percent as the probability for inclusion
            if random.random() * 100 < max_percent:
                hardcoded_dict[int(asn)] = RealROVSimplePolicy
    return frozendict(hardcoded_dict)


def get_us_country_asns() -> frozenset[int]:
    bgp_dag = CAIDAASGraphConstructor(tsv_path=None).run()
    return frozenset([x for x in get_country_asns("US") if x in bgp_dag.as_dict])
