from multiprocessing import cpu_count
from pathlib import Path
import shutil
import sys

from bgpy.enums import ASGroups, SpecialPercentAdoptions
from bgpy.simulation_engine import ROVSimplePolicy
from bgpy.simulation_framework import ScenarioConfig, Simulation

from .policies import (
    GuardValid24,
    GuardValidNot24,
    GuardNotValid24,
    GuardNotValidNot24,
    Dest24,
    DestValidNot24,
    DestNotValidNot24,

)
from .tor_relay_collector import TORRelayCollector, print_relay_stats
from .scenarios import (
    ClientsToGuardScenario,
    ExitToDestScenario,
)
from .utils import get_us_country_asns, get_real_world_rov_asn_cls_dict


def main():

    relays = TORRelayCollector().run()
    print_relay_stats(relays)

    rov_dict = get_real_world_rov_asn_cls_dict()

    us_asns = get_us_country_asns()

    BASE_PATH = Path.home() / "Desktop" / "tor"

    default_kwargs = {
        "python_hash_seed": 0,
        "percent_adoptions": (
            SpecialPercentAdoptions.ONLY_ONE,
            0.1,
            0.3,
            0.5,
            0.8,
            0.99
        ),
        "num_trials": 1 if "quick" in str(sys.argv) else 500,
        "parse_cpus": cpu_count(),
    }
    guard_classes = (GuardValid24, GuardValidNot24, GuardNotValid24, GuardNotValidNot24)
    dest_classes = (Dest24, DestValidNot24, DestNotValidNot24)

    """
    sim = Simulation(
        scenario_configs=tuple(
            [
                ScenarioConfig(
                    ScenarioCls=ClientsToGuardScenario,
                    AdoptPolicyCls=AdoptPolicyCls,
                    hardcoded_asn_cls_dict=rov_dict,
                )
                for AdoptPolicyCls in guard_classes
            ]
        ),
        output_dir=BASE_PATH / "client_to_guard_single_attacker",
        **default_kwargs,  # type: ignore
    )
    sim.run()

    sim = Simulation(
        scenario_configs=tuple(
            [
                ScenarioConfig(
                    ScenarioCls=ClientsToGuardScenario,
                    AdoptPolicyCls=AdoptPolicyCls,
                    hardcoded_asn_cls_dict=rov_dict,
                    override_attacker_asns=us_asns,
                    num_attackers=len(us_asns),
                )
                for AdoptPolicyCls in guard_classes
            ]
        ),

        output_dir=BASE_PATH / "client_to_guard_us",
        **default_kwargs,  # type: ignore
    )
    sim.run()
    """

    sim = Simulation(
        scenario_configs=tuple(
            [
                ScenarioConfig(
                    ScenarioCls=ExitToDestScenario,
                    AdoptPolicyCls=AdoptPolicyCls,
                    hardcoded_asn_cls_dict=rov_dict,
                    attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
                    propagation_rounds=2,
                )
                for AdoptPolicyCls in dest_classes
            ]
        ),
        output_dir=BASE_PATH / "exit_to_dest_mh",
        **default_kwargs,  # type: ignore
    )
    sim.run()

    sim = Simulation(
        scenario_configs=tuple(
            [
                ScenarioConfig(
                    ScenarioCls=ExitToDestScenario,
                    AdoptPolicyCls=AdoptPolicyCls,
                    hardcoded_asn_cls_dict=rov_dict,
                    attacker_subcategory_attr=ASGroups.MULTIHOMED.value,
                    override_attacker_asns=us_asns,
                    num_attackers=len(us_asns),
                    propagation_rounds=2,
                )
                for AdoptPolicyCls in dest_classes
            ]
        ),

        output_dir=BASE_PATH / "exit_to_dest_us",
        **default_kwargs,  # type: ignore
    )
    sim.run()


    shutil.make_archive(str(BASE_PATH.parent / "tor.zip"), "zip", str(BASE_PATH))


if __name__ == "__main__":
    main()
