tor_relay_ipv4_origin_guard_dict= get_tor_relay_ipv4_origin_guard_dict()
tor_relay_ipv4_origin_guard_keys = tuple(list(tor_relay_ipv4_origin_guard_dict.keys()))


class ClientToGaurdScenario(Scenario):
    """Attacker attempts to intercept traffic from client to gaurd by mitm gaurd"""

    tor_relay_ipv4_origin_guard_dict = tor_relay_ipv4_origin_guard_dict
    tor_relay_ipv4_origin_guard_keys = tor_relay_ipv4_origin_guard_keys
    tor_relay_ipv4_origin_guard_counter = 0

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
            self.tor_relay = prev_scenario.tor_relay
        else:
            try:
                origin_guard_asn = self.tor_relay_ipv4_origin_guard_keys[
                    self.tor_relay_ipv4_origin_guard_counter
                ]
            except IndexError:
                print("You have more trials than there are TOR ASNs")
                raise
            self.tor_relay = self.tor_relay_ipv4_origin_guard_dict[origin_guard_asn][0]
            self.tor_relay_ipv4_origin_guard_counter += 1

        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=prev_scenario,
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
            [x for x in self.engine if x.asn != self.tor_relay.ipv4_origin]
        )
        # NOTE: this is just to get results quickly for the paper. DONT
        # USE THIS ELSEWHERE!
        del self.engine
        return untracked_asns

    def get_announcements(self, *args, **kwargs) -> tuple["Ann", ...]:
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
        assert len(self.victim_asns == 1, "How is there >1 relay?"
        [victim_asn] = self.victim_asns
        assert victim_asn == self.tor_relay.ipv4_origin
        if self.tor_relay.ipv4_roa_validity.is_valid():
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

        for attacker_asn in self.attacker_asns:
            # Covered by a ROA
            if roa_length is not None:
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
