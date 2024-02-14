import random
from typing import Optional, Union

from frozendict import frozendict

from bgpy.enums import SpecialPercentAdoptions, Timestamps, Relationships
from bgpy.simulation_engine import BaseSimulationEngine, Announcement as Ann
from bgpy.simulation_engine import Policy
from bgpy.simulation_framework import Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    noop,
    PREPROCESS_ANNS_FUNC_TYPE,
)

from roa_checker import ROAValidity

from ..tor_relay_collector import get_tor_relay_groups, TORRelay


class ClientsToGuardScenario(Scenario):
    """Attacker attempts to intercept traffic from client to gaurd by mitm gaurd

    Here, the attacker can simply NAT the traffic to the guard through a cloud provider,
    so we don't need to worry about keeping a route alive
    """

    tor_relay_groups_dict: frozendict[Policy, tuple[TORRelay, ...]] = (
        get_tor_relay_groups()
    )

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
                self.tor_relay_groups[self.scenario_config.AdoptPolicyCls]
            )
        except KeyError:
            raise KeyError(
                "This Scenario only supports {list(self.tor_relay_groups)} for "
                f"AdoptPolicyCls, but you used {self.scenario_config.AdoptPolicyCls}"
            )

        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=engine,
            prev_scenario=prev_scenario,
            preprocess_anns_func=preprocess_anns_func,
        )
        assert self.scenario_config.AdoptPolicyCls == self.tor_relay_policy

    def _get_possible_victim_asns(self, *args, **kwargs) -> frozenset[int]:
        """Returns possible victim ASNs, defaulted from config"""

        assert self.num_victims == 1, "Only 1 victim allowed for this class"
        return frozenset([self.tor_relay.ipv4_origin])

    def _get_announcements(self, *args, **kwargs) -> tuple["Ann", ...]:

        """Returns announcements

        Attacker strategy:

        If relay prefix is not covered by a ROA:
            if prefix == /24:
                prefix hijack gaurd
            if prefix shorter than /24:
                subprefix interception attack gaurd
        if relay prefix IS covered by a ROA:
            if prefix == /24:
                origin_guard prefix hijack guard
            if prefix shorter than /24:
                origin_guard prefix hijack guard
                subperfix interception attack guard
        """

        anns = list()

        # Victim
        assert self.scenario_config.num_victims == 1, "How is there >1 relay?"
        assert len(self.victim_asns) == 1, "How is there >1 relay?"
        [victim_asn] = self.victim_asns
        assert victim_asn == self.tor_relay.ipv4_origin
        if ROAValidity.is_valid(self.tor_relay.ipv4_roa_validity):
            roa_valid_length = True
            roa_origin = victim_asn
        else:
            roa_valid_length = None
            roa_origin = None

        # Victim/tor relay's ann
        anns.append(
            self.scenario_config.AnnCls(
                prefix=str(self.tor_relay.ipv4_prefix),
                next_hop_asn=self.tor_relay.ipv4_origin,
                as_path=(self.tor_relay.ipv4_origin,),
                timestamp=Timestamps.VICTIM.value,
                seed_asn=self.tor_relay.ipv4_origin,
                roa_valid_length=roa_valid_length,
                roa_origin=roa_origin,
                recv_relationship=Relationships.ORIGIN,
            )
        )

        # If victim is in attacker asns, that's an auto-win for attacker
        # so don't waste the compution time by adding lots of anns
        if victim_asn not in self.attacker_asns:
            for attacker_asn in self.attacker_asns:
                # Covered by a ROA
                if roa_valid_length is not None:
                    # Can't be more specific than a /24
                    if self.tor_relay.ipv4_prefix.prefixlen == 24:
                        # origin prefix hijack
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=str(self.tor_relay.ipv4_prefix),
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn, victim_asn),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=True,
                                roa_origin=victim_asn,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                    else:
                        # origin prefix hijack
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=str(self.tor_relay.ipv4_prefix),
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn, victim_asn),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=True,
                                roa_origin=victim_asn,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                        # Also a subprefix hijack for non-ROV nodes
                        prefix = str(self.tor_relay.ipv4_prefix)
                        plen = self.tor_relay.ipv4_prefix.prefixlen
                        prefix = prefix.replace(f"/{plen}", f"/{plen + 1}")
                        print("CHECK THIS!!!!!")
                        print(str(self.tor_relay.ipv4_prefix))
                        input(prefix)
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=prefix,
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn,),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=False,
                                roa_origin=victim_asn,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                # Not covered by a ROA
                else:
                    # Can't be more specific than a /24
                    if self.tor_relay.ipv4_prefix.prefixlen == 24:
                        # prefix hijack, unknown by ROA
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=str(self.tor_relay.ipv4_prefix),
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn,),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=None,
                                roa_origin=None,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                    else:
                        # prefix hijack, unknown by ROA
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=str(self.tor_relay.ipv4_prefix),
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn,),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=None,
                                roa_origin=None,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                        # Also a subprefix hijack, unknown bu ROA
                        prefix = str(self.tor_relay.ipv4_prefix)
                        plen = self.tor_relay.ipv4_prefix.prefixlen
                        prefix = prefix.replace(f"/{plen}", f"/{plen + 1}")
                        anns.append(
                            self.scenario_config.AnnCls(
                                prefix=prefix,
                                next_hop_asn=attacker_asn,
                                as_path=(attacker_asn,),
                                timestamp=Timestamps.ATTACKER.value,
                                seed_asn=attacker_asn,
                                roa_valid_length=None,
                                roa_origin=None,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
        return tuple(anns)
