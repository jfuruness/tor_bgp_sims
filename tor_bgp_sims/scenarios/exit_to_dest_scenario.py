from bgpy.enums import Timestamps, Relationships, SpecialPercentAdoptions
from bgpy.simulation_engine import BaseSimulationEngine, Announcement as Ann
from bgpy.simulation_framework import AccidentalRouteLeak

from .tor_scenario import TORScenario
from ..policies import Dest24, DestValidNot24, DestNotValidNot24


class ExitToDestScenario(TORScenario):
    """Attacker attempts to intercept traffic from dest to mitm exit

    Here we need to worry about keeping a route alive,
    so only interception attacks

    Additionally - we can't inhereit from accidental route leak...
    too much is different
    """

    min_propagation_rounds: int = 2

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        super().__init__(*args, **kwargs)
        if (
            self.scenario_config.attacker_subcategory_attr in self.warning_as_groups
            and not self.scenario_config.override_attacker_asns
        ):
            msg = (
                "You used the ASGroup of "
                f"{self.scenario_config.attacker_subcategory_attr} "
                f"for your scenario {self.__class__.__name__}, "
                f"but {self.__class__.__name__} can't leak from stubs. "
                "To suppress this warning, override warning_as_groups"
            )
            warnings.warn(msg, RuntimeWarning)

    warning_as_groups = AccidentalRouteLeak.warning_as_groups

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
        return untracked_asns

    def _get_announcements(self, *args, **kwargs) -> tuple["Ann", ...]:
        """Returns a valid prefix announcement

        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        for victim_asn in self.victim_asns:
            if self.scenario_config.AdoptPolicyCls == Dest24:
                roa_valid_length = True
                roa_origin = victim_asn
                prefix = "1.2.3.0/24"
            elif self.scenario_config.AdoptPolicyCls == DestValidNot24:
                roa_valid_length = True
                roa_origin = victim_asn
                prefix = "1.2.0.0/16"
            elif self.scenario_config.AdoptPolicyCls == DestNotValidNot24:
                roa_valid_length = None
                roa_origin = None
                prefix = "1.2.0.0/16"
            else:
                raise NotImplementedError("Not supported")

            anns.append(
                self.scenario_config.AnnCls(
                    prefix=prefix,
                    next_hop_asn=victim_asn,
                    as_path=(victim_asn,),
                    timestamp=Timestamps.VICTIM.value,
                    seed_asn=victim_asn,
                    roa_valid_length=roa_valid_length,
                    roa_origin=roa_origin,
                    recv_relationship=Relationships.ORIGIN,
                )
            )
        return tuple(anns)

    def post_propagation_hook(
        self,
        engine: "BaseSimulationEngine",
        percent_adopt: float | SpecialPercentAdoptions,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Causes an accidental route leak

        Changes the valid prefix to be received from a customer
        so that in the second propagation round, the AS will export to all
        relationships

        NOTE: the old way of doing this was to simply alter the attackers
        local RIB and then propagate again. However - this has some drawbacks
        Then the attacker must deploy BGPPolicy (that uses withdrawals) and
        the entire graph has to propagate again. BGPPolicy (and subclasses
        of it) are MUCH slower than BGPSimplePolicy due to all the extra
        computations for withdrawals, RIBsIn, RIBsOut, etc. Additionally,
        propagating a second round after the ASGraph is __already__ full
        is wayyy more expensive than propagating when the AS graph is empty.

        Instead, we now get the announcement that the attacker needs to leak
        after the first round of propagating the valid prefix.
        Then we clear the graph, seed those announcements, and propagate again
        This way, we avoid needing BGPPolicy (since the graph has been cleared,
        there is no need for withdrawals), and we avoid propagating a second
        time after the graph is alrady full.

        Since this simulator treats each propagation round as if it all happens
        at once, this is possible.

        Additionally, you could also do the optimization in the first propagation
        round to only propagate from ASes that can reach the attacker. But we'll
        forgo this for now for simplicity.

        NOTE: EXTENSIONS FOR THE TOR PAPER
        if prefix is shorter than /24, add a subprefix interception attack
        """

        if propagation_round == 0:
            announcements: list["Ann"] = list(self.announcements)  # type: ignore
            for attacker_asn in self.attacker_asns:
                if not engine.as_graph.as_dict[attacker_asn].policy._local_rib:
                    print("Attacker did not recieve announcement, can't leak. ")
                for prefix, ann in engine.as_graph.as_dict[
                    attacker_asn
                ].policy._local_rib.items():
                    announcements.append(
                        ann.copy(
                            {
                                "recv_relationship": Relationships.CUSTOMERS,
                                "seed_asn": attacker_asn,
                                "traceback_end": True,
                                "timestamp": Timestamps.ATTACKER.value,
                            }
                        )
                    )
                    prefix_len = int(prefix.split("/")[-1])
                    if prefix_len < 24:
                        if ann.roa_valid_length is not None:
                            roa_origin = ann.roa_origin
                            roa_valid_length = False
                        else:
                            roa_origin = ann.roa_origin
                            roa_valid_length = None
                        announcements.append(
                            ann.copy(
                                {
                                    "prefix": prefix.replace(
                                        str(prefix_len), str(prefix_len + 1)
                                    ),
                                    "roa_origin": roa_origin,
                                    "roa_valid_length": roa_valid_length,
                                    "recv_relationship": Relationships.CUSTOMERS,
                                    "seed_asn": attacker_asn,
                                    "traceback_end": True,
                                    "timestamp": Timestamps.ATTACKER.value,
                                }
                            )
                        )

            self.announcements = tuple(announcements)
            self.ordered_prefix_subprefix_dict: dict[
                str, list[str]
            ] = self._get_ordered_prefix_subprefix_dict()

            self.setup_engine(engine)
            engine.ready_to_run_round = 1
        elif propagation_round > 1:
            raise NotImplementedError
