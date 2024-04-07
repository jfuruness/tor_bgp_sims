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
from tor_bgp_sims.policies import (
    GuardValid24,
    GuardValidNot24,
    GuardNotValid24,
    GuardNotValidNot24,
    Dest24,
    DestValidNot24,
    DestNotValidNot24,
)


class ClientsToGuardExitToDestScenario(Scenario)
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

        try:
            self.guard_tor_relay = random.choice(
                self.tor_relay_groups_dict[scenario_config.AdoptPolicyCls]
            )
            self.exit_tor_relay = random.choice(
                self.tor_relay_groups_dict[self.DestAdoptPolicyCls]
            )
        except KeyError:
            raise KeyError(
                f"This Scenario only supports {list(self.tor_relay_groups_dict)} for "
                f"AdoptPolicyCls, but you used {self.scenario_config.AdoptPolicyCls}"
            )

    @property
    def DestAdoptPolicyCls(self) -> Policy:
        """Returns the corresponding destination policy class"""

        if self.scenario_config.AdoptPolicyCls in (GuardValid24, GuardNotValid24):
            return Dest24
        elif self.scenario_config.AdoptPolicyCls == GuardValidNot24:
            return DestValidNot24
        elif self.scenario_config.AdoptPolicyCls == GuardNotValidNot24:
            return DestNotValidNot24
        else:
            raise NotImplementedError("Case not accounted for")

    def _get_victim_asns(
        self,
        override_victim_asns: Optional[frozenset[int]],
        engine: Optional[BaseSimulationEngine],
        prev_scenario: Optional["Scenario"],
    ) -> frozenset[int]:
        """Unlike the parent class, we always want a new victim for same trial

        this is because we are choosing different relays every time
        """

        # This will force the call of _get_possible_victim_asns since we are
        # forcing this to not reuse victims from last scenario
        # we leave override victim asns since this is only true for tests
        return super()._get_victim_asns(
            override_victim_asns=override_victim_asns, engine=engine, prev_scenario=None
        )

    def _get_possible_victim_asns(self, *args, **kwargs) -> frozenset[int]:
        """Returns possible victim ASNs

        We override this to only return 2 victims to force these victims to be chosen
        a bit hacky but whatevs

        first victim is for the guard relay. Second is for the destination prefix
        """
        possible_exit_victim_asns = super()._get_possible_victim_asns(*args, **kwargs)
        possible_exit_victim_asns = possible_exit_victim_asns.difference(
            set([self.guard_tor_relay.ipv4_origin])
        )
        # https://stackoverflow.com/a/15837796/8903959
        exit_victim_asn = random.choice(tuple(possible_exit_victim_asns))

        assert self.scenario_config.num_victims == 2, "Need guard and dest victims"
        return frozenset([self.guard_tor_relay.ipv4_origin, exit_victim_asn])
