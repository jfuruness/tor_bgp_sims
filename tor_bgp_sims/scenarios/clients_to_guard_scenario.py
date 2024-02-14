from typing import Optional

from bgpy.enums import Timestamps, Relationships
from bgpy.simulation_engine import BaseSimulationEngine, Announcement as Ann
from bgpy.simulation_framework import Scenario

from roa_checker import ROAValidity

from .tor_scenario import TORScenario


class ClientsToGuardScenario(TORScenario):
    """Attacker attempts to intercept traffic from client to gaurd by mitm gaurd

    Here, the attacker can simply NAT the traffic to the guard through a cloud provider,
    so we don't need to worry about keeping a route alive
    """

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
            override_victim_asns=override_victim_asns,
            engine=engine,
            prev_scenario=None
        )

    def _get_possible_victim_asns(self, *args, **kwargs) -> frozenset[int]:
        """Returns possible victim ASNs, defaulted from config"""

        assert self.scenario_config.num_victims == 1, "Only 1 victim allowed"
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
                    if self.tor_relay.ipv4_prefix.prefixlen < 24:
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
                    if self.tor_relay.ipv4_prefix.prefixlen < 24:
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
