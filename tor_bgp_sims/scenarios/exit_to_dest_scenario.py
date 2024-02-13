import random
from typing import Optional, Union

from bgpy.enums import SpecialPercentAdoptions
from bgpy.simulation_engine import BaseSimulationEngine
from bgpy.simulation_framework import AccidentalRouteLeak, Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    noop,
    PREPROCESS_ANNS_FUNC_TYPE,
)

from ..tor_relay_collector import get_tor_relay_ipv4_origin_exit_dict, TORRelay

tor_relay_ipv4_origin_exit_dict = get_tor_relay_ipv4_origin_exit_dict()
tor_relay_ipv4_origin_exit_keys = tuple(list(tor_relay_ipv4_origin_exit_dict.keys()))


class ExitToDestScenario(AccidentalRouteLeak):
    """Attacker attempts to intercept traffic from exit to dest to mitm dest

    Can't use cloud providers here - need to keep connection alive

    NOTE: we use accidental route leak here since we assume that dest is always /24
    """

    tor_relay_ipv4_origin_exit_dict = tor_relay_ipv4_origin_exit_dict
    tor_relay_ipv4_origin_exit_keys = tor_relay_ipv4_origin_exit_keys
    tor_relay_ipv4_origin_exit_counter: dict[
        float | SpecialPercentAdoptions, int
    ] = dict()

    def __init__(
        self,
        *,
        scenario_config: ScenarioConfig,
        percent_adoption: Union[float, SpecialPercentAdoptions] = 0,
        engine: Optional[BaseSimulationEngine] = None,
        prev_scenario: Optional["Scenario"] = None,
        preprocess_anns_func: PREPROCESS_ANNS_FUNC_TYPE = noop,
    ):
        """Adds TOR relay to the scenario

        There are only 593 unique IPV4 ASNs for exit relays
        We just simulate each ASN once
        """

        # Add the TOR relay to the scenario
        if prev_scenario:
            assert isinstance(prev_scenario, ExitToDestScenario), "for mypy"
            self.tor_relay: TORRelay = prev_scenario.tor_relay
        else:
            try:
                counter = self.tor_relay_ipv4_origin_exit_counter.get(
                    percent_adoption, 0
                )
                origin_exit_asn = self.tor_relay_ipv4_origin_exit_keys[counter]
            except IndexError:
                self.tor_relay_ipv4_origin_exit_counter[percent_adoption] = 0
                counter = 0
                origin_exit_asn = self.tor_relay_ipv4_origin_exit_keys[counter]
            self.tor_relay = random.choice(
                self.tor_relay_ipv4_origin_exit_dict[origin_exit_asn]
            )
            self.tor_relay_ipv4_origin_exit_counter[percent_adoption] = (
                self.tor_relay_ipv4_origin_exit_counter.get(percent_adoption, 0) + 1
            )

        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=engine,
            prev_scenario=prev_scenario,
            preprocess_anns_func=preprocess_anns_func,
        )
        assert engine
        self.engine = engine

    @property
    def _untracked_asns(self) -> frozenset[int]:
        """Anything in this list won't be tracked

        Since we only want to traceback from exit and don't care about
        other nodes, add everything other than exit to here
        """

        assert self.engine
        untracked_asns = frozenset(
            [x.asn for x in self.engine.as_graph if x.asn != self.tor_relay.ipv4_origin]
        )
        # NOTE: this is just to get results quickly for the paper. DONT
        # USE THIS ELSEWHERE!
        # del self.engine
        return untracked_asns
