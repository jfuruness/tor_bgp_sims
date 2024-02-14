from collections import Counter
from multiprocessing import cpu_count
from pathlib import Path
import shutil
import sys

from frozendict import frozendict

from bgpy.as_graphs import CAIDAASGraphConstructor
from bgpy.enums import ASGroups, SpecialPercentAdoptions
from bgpy.simulation_engine import ROVSimplePolicy, Policy
from bgpy.simulation_framework import ScenarioConfig, Simulation
from bgpy.simulation_framework.utils import get_country_asns

from roa_checker import ROAValidity

from .tor_graph_factory import TORGraphFactory
from .tor_relay_collector import TORRelayCollector
from .scenarios import (
    ClientToGuardScenario,
    ExitToDestScenario,
    fifty_percent_covered_by_roa,
)


class RealROVSimplePolicy(ROVSimplePolicy):
    name = "RealROV"


def main():

    relays = TORRelayCollector().run()
    print_relay_stats(relays)

    json_path: Path = Path.home() / "Desktop" / "rov_info.json"

    if not json_path.exists():
        # NOTE: This breaks pip. Just install individually for now
        from rov_collector import rov_collector_classes

        for CollectorCls in rov_collector_classes:
            CollectorCls(json_path=json_path).run()  # type: ignore

    python_hash_seed = 0

    def get_real_world_rov_asn_cls_dict():
        import json
        import random

        random.seed(python_hash_seed)
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

    rov_dict = get_real_world_rov_asn_cls_dict()

    bgp_dag = CAIDAASGraphConstructor(tsv_path=None).run()
    us_asns = frozenset([x for x in get_country_asns("US") if x in bgp_dag.as_dict])
    del bgp_dag  # let RAM be reclaimed

    BASE_PATH = Path.home() / "Desktop" / "tor"

    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE,),# 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ClientToGuardScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
            ),
        ),
        output_dir=BASE_PATH / "client_to_guard_single_attacker",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_gaurds),
        parse_cpus=cpu_count(),
    )
    run_kwargs = {
        "GraphFactoryCls": TORGraphFactory,
        "graph_factory_kwargs": {
            "label_replacement_dict": {
                Policy.name: "Aggregate",
            }
        }
    }
    sim.run(**run_kwargs)
    # Oof, so janky. No no no.
    ClientToGuardScenario.tor_relay_ipv4_origin_guard_counter = dict()
    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE, 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ClientToGuardScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
                override_attacker_asns=us_asns,
            ),
        ),
        output_dir=BASE_PATH / "client_to_guard_us",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_gaurds),
        parse_cpus=cpu_count(),
    )
    sim.run(**run_kwargs)
    ClientToGuardScenario.tor_relay_ipv4_origin_guard_counter = dict()
    """
    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE, 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ClientToGuardScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
                attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
            ),
        ),
        output_dir=BASE_PATH / "client_to_guard_mh",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_gaurds),
        parse_cpus=cpu_count(),
    )
    sim.run(**run_kwargs)
    # Oof, so janky. No no no.
    ClientToGuardScenario.tor_relay_ipv4_origin_guard_counter = dict()
    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE, 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ClientToGuardScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
                attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
                override_attacker_asns=us_asns,
            ),
        ),
        output_dir=BASE_PATH / "client_to_guard_us_mh",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_gaurds),
        parse_cpus=cpu_count(),
    )
    sim.run(**run_kwargs)
    ClientToGuardScenario.tor_relay_ipv4_origin_guard_counter = dict()
    """

    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE, 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ExitToDestScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
                attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
                preprocess_anns_func=fifty_percent_covered_by_roa,
            ),
        ),
        output_dir=BASE_PATH / "exit_to_dest_mh",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_exits),
        parse_cpus=cpu_count(),
        propagation_rounds=2,  # Required for leakage
    )
    sim.run(**run_kwargs)
    ExitToDestScenario.tor_relay_ipv4_origin_exit_counter = dict()

    sim = Simulation(
        python_hash_seed=python_hash_seed,
        # We don't need percent adoptions here...
        percent_adoptions=(SpecialPercentAdoptions.ONLY_ONE, 0.1, 0.3, 0.5, 0.8, 0.99),
        scenario_configs=(
            ScenarioConfig(
                ScenarioCls=ExitToDestScenario,
                AdoptPolicyCls=ROVSimplePolicy,
                hardcoded_asn_cls_dict=rov_dict,
                attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
                override_attacker_asns=us_asns,
                preprocess_anns_func=fifty_percent_covered_by_roa,
            ),
        ),
        output_dir=BASE_PATH / "exit_to_dest_us",
        num_trials=1 if "quick" in str(sys.argv) else len(unique_asn_ipv4_exits),
        parse_cpus=cpu_count(),
        propagation_rounds=2,  # Required for leakage
    )
    sim.run(**run_kwargs)
    ExitToDestScenario.tor_relay_ipv4_origin_exit_counter = dict()

    shutil.make_archive(str(BASE_PATH.parent / "tor.zip"), "zip", str(BASE_PATH))


if __name__ == "__main__":
    main()
