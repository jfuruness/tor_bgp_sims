import random
from typing import Optional, Union

from frozendict import frozendict

from bgpy.enums import SpecialPercentAdoptions
from bgpy.simulation_engine import BaseSimulationEngine
from bgpy.simulation_engine import Policy
from bgpy.simulation_framework import Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    noop,
    PREPROCESS_ANNS_FUNC_TYPE,
)

from ..tor_relay_collector import get_tor_relay_groups, TORRelay


class TORScenario(Scenario):
    """TOR Scenario that selects a relay based on adopt policy"""

    tor_relay_groups_dict: frozendict[
        type[Policy], tuple[TORRelay, ...]
    ] = get_tor_relay_groups()

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

        This also checks that the AdoptPolicyCls is a supported one

        The way this works is that the adopt policy class is used to determine
        the type of tor relay, and then a tor relay of that type is randomly
        selected. This allows us to compare attacks against multiple types
        of tor relays

        The reason that this is set to the AdoptPolicyCls is merely because the
        GraphFactoryCls uses that when creating the graph lines, so by doing
        it this way we won't need to modify the GraphFactory class
        """

        try:
            self.tor_relay = random.choice(
                self.tor_relay_groups_dict[scenario_config.AdoptPolicyCls]
            )
        except KeyError:
            raise KeyError(
                f"This Scenario only supports {list(self.tor_relay_groups_dict)} for "
                f"AdoptPolicyCls, but you used {self.scenario_config.AdoptPolicyCls}"
            )

        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=engine,
            prev_scenario=prev_scenario,
            preprocess_anns_func=preprocess_anns_func,
        )

        # Needed for the untracked asns in the exit to dest scenario
        assert engine
        self.engine = engine
