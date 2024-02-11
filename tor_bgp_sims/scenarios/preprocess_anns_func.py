from collections import deque
from typing import Callable, Optional, TYPE_CHECKING

from bgpy.simulation_engine import BGPPolicy, ASPASimplePolicy, PathendSimplePolicy

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.simulation_framework.scenario import Scenario
    from bgpy.simulation_engine import Announcement as Ann, BaseSimulationEngine
    from bgpy.simulation_engine import Policy


def fifty_percent_covered_by_roa(
    self_scenario: "Scenario",
    unprocessed_anns: tuple["Ann", ...],
    engine: Optional["BaseSimulationEngine"],
    prev_scenario: Optional["Scenario"],
) -> tuple["Ann", ...]:
    """Makes the attack use an origin hijack to be valid by ROA"""

    assert len(unprocessed_anns) == 1, "Meant for valid prefix only"

    # 50% chance of being covered by a ROA
    if bool(random.randint(0, 1)):
        processed_anns = list()
        for ann in unprocessed_anns:
            processed_anns.append(
                ann.copy(
                    {
                        "roa_valid_length": None,
                        "roa_origin": None,
                        # Ann.copy overwrites seed_asn and traceback by default
                        # so include these here to make sure that doesn't happen
                        "seed_asn": ann.seed_asn,
                        "traceback_end": ann.traceback_end,
                    }
                )
            )
        return tuple(processed_anns)
    else:
        return unprocessed_anns
