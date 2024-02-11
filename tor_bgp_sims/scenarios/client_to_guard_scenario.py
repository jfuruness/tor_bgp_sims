from typing import Optional, Union

from bgpy.enums import SpecialPercentAdoptions, Timestamps, Relationships
from bgpy.simulation_engine import BaseSimulationEngine, Announcement as Ann
from bgpy.simulation_framework import Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    noop,
    PREPROCESS_ANNS_FUNC_TYPE,
)

from roa_checker import ROAValidity

from ..tor_relay_collector import get_tor_relay_ipv4_origin_guard_dict, TORRelay

tor_relay_ipv4_origin_guard_dict = get_tor_relay_ipv4_origin_guard_dict()
tor_relay_ipv4_origin_guard_keys = tuple(list(tor_relay_ipv4_origin_guard_dict.keys()))


class ClientToGuardScenario(Scenario):
    """Attacker attempts to intercept traffic from client to gaurd by mitm gaurd

    Here, the attacker can simply NAT the traffic to the guard through a cloud provider,
    so we don't need to worry about keeping a route alive
    """

    tor_relay_ipv4_origin_guard_dict = tor_relay_ipv4_origin_guard_dict
    tor_relay_ipv4_origin_guard_keys = tor_relay_ipv4_origin_guard_keys
    tor_relay_ipv4_origin_guard_counter: dict[
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

        There are only 593 unique IPV4 ASNs for guard relays
        We just simulate each ASN once
        """

        # Add the TOR relay to the scenario
        if prev_scenario:
            assert isinstance(prev_scenario, ClientToGuardScenario), "for mypy"
            self.tor_relay: TORRelay = prev_scenario.tor_relay
        else:
            try:
                counter = self.tor_relay_ipv4_origin_guard_counter.get(
                    percent_adoption, 0
                )
                origin_guard_asn = self.tor_relay_ipv4_origin_guard_keys[counter]
            except IndexError:
                print("You have more trials than there are TOR ASNs")
                raise
            self.tor_relay = self.tor_relay_ipv4_origin_guard_dict[origin_guard_asn][0]
            self.tor_relay_ipv4_origin_guard_counter[percent_adoption] = (
                self.tor_relay_ipv4_origin_guard_counter.get(percent_adoption, 0) + 1
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

    def _get_possible_victim_asns(self, *args, **kwargs) -> frozenset[int]:
        """Returns possible victim ASNs, defaulted from config"""

        return frozenset([self.tor_relay.ipv4_origin])

    @property
    def _untracked_asns(self) -> frozenset[int]:
        """Anything in this list won't be tracked

        Since we only want to traceback from guard and don't care about
        other notes, add everything other than guard to here
        """

        assert self.engine
        untracked_asns = frozenset(
            [x for x in self.engine.as_graph if x.asn != self.tor_relay.ipv4_origin]
        )
        # NOTE: this is just to get results quickly for the paper. DONT
        # USE THIS ELSEWHERE!
        # del self.engine
        return untracked_asns

    def _get_announcements(self, engine, *args, **kwargs) -> tuple["Ann", ...]:
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
        # so don't waste the compution time
        if victim_asn not in self.attacker_asns:
            for attacker_asn in self.attacker_asns:
                # Don't add attackers that aren't in the graph
                if attacker_asn not in engine.as_graph.as_dict:
                    continue
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
                                roa_valid_length=False,
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
                                roa_valid_length=False,
                                roa_origin=victim_asn,
                                recv_relationship=Relationships.ORIGIN,
                            )
                        )
                        # Also a subprefix hijack for non-ROV nodes
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
