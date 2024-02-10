from typing import Optional, Union

from bgpy.enums import SpecialPercentAdoptions, Timestamps, Relationships
from bgpy.simulation_engine import BaseSimulationEngine, Announcement as Ann
from bgpy.simulation_framework import Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    noop, PREPROCESS_ANNS_FUNC_TYPE
)
from bgpy.simulation_framework.utils import get_country_asns

from roa_checker import ROAValidity

from .client_to_guard_scenario import ClientToGuardScenario
from ..tor_relay_collector import get_tor_relay_ipv4_origin_guard_dict

tor_relay_ipv4_origin_guard_dict = get_tor_relay_ipv4_origin_guard_dict()
tor_relay_ipv4_origin_guard_keys = tuple(list(tor_relay_ipv4_origin_guard_dict.keys()))


class USClientToGuardScenario(ClientToGuardScenario):
    """Attacker attempts to intercept traffic from client to gaurd by mitm gaurd"""

    tor_relay_ipv4_origin_guard_dict = tor_relay_ipv4_origin_guard_dict
    tor_relay_ipv4_origin_guard_keys = tor_relay_ipv4_origin_guard_keys
    tor_relay_ipv4_origin_guard_counter = dict()

    def _get_announcements(self, engine, prev_scenario) -> tuple["Ann", ...]:
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
        assert self.num_victims == 1, "How is there >1 relay?"
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
