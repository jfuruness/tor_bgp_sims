from collections import defaultdict
from functools import cached_property
import gc
from itertools import product
from pathlib import Path
import pickle
from typing import Any

import matplotlib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
from tqdm import tqdm

from bgpy.simulation_framework.metric_tracker.metric_key import MetricKey
from bgpy.simulation_framework.utils import get_all_metric_keys

from bgpy.enums import SpecialPercentAdoptions
from bgpy.simulation_engine import Policy

from .policies import (
    GuardValid24,
    GuardValidNot24,
    GuardNotValid24,
    GuardNotValidNot24,
    DestValid,
    DestNotCovered,
)
from bgpy.simulation_framework import GraphFactory


class TORGraphFactory(GraphFactory):
    """Automates graphing of default graphs"""

    def generate_graphs(self) -> None:
        """Generates default graphs"""

        # Each metric key here contains plane, as group, and outcome
        # In other words, aech type of graph

        # NOTE: CHANGED! We don't need adopting or non adopting we only need Any
        # which captures TOR Relay info
        graph_infos = list(product(self.metric_keys, [Any]))

        for metric_key, adopting in tqdm(
            graph_infos, total=len(graph_infos), desc="Writing Graphs"
        ):
            relevant_rows = list()
            for row in self.graph_rows:
                # Get all the rows that correspond to that type of graph
                BasePolicyCls = row["data_key"].scenario_config.BasePolicyCls
                AdoptPolicyCls = row["data_key"].scenario_config.AdoptPolicyCls
                if (
                    row["metric_key"].plane == metric_key.plane
                    and row["metric_key"].as_group == metric_key.as_group
                    and row["metric_key"].outcome == metric_key.outcome
                    # NOTE: CHANGED! We need to extract specific policies
                    # and (
                    #     (
                    #         row["metric_key"].PolicyCls == BasePolicyCls
                    #         and adopting is False
                    #     )
                    #     or (
                    #         row["metric_key"].PolicyCls == AdoptPolicyCls
                    #         and adopting is True
                    #     )
                    #     or (row["metric_key"].PolicyCls == Policy and adopting is Any)
                    # )
                    and row["metric_key"].PolicyCls in (
                        GuardValid24,
                        GuardValidNot24,
                        GuardNotValid24,
                        GuardNotValidNot24,
                        DestValid,
                        DestNotCovered,
                        Policy,
                    )
                ):
                    relevant_rows.append(row)

            self._generate_graph(metric_key, relevant_rows, adopting=adopting)

    def _generate_graph(self, metric_key: MetricKey, relevant_rows, adopting) -> None:
        """Writes a graph to the graph dir"""

        # Row is:
        # data_key: DataKey
        #    propagation_round
        #    percent_adopt
        #    scenario_config
        # metric_key: MetricKey
        #     Plane
        #     as_group
        #     outcome
        #     PolicyCls
        # Value: float
        # Yerr: yerr

        if not relevant_rows:
            return
        adopting_str = str(adopting) if isinstance(adopting, bool) else "Any"
        scenario_config = relevant_rows[0]["data_key"].scenario_config
        mod_name = scenario_config.preprocess_anns_func.__name__
        graph_name = (
            f"{scenario_config.ScenarioCls.__name__}_{mod_name}"
            f"/{metric_key.as_group.value}"
            f"/adopting_is_{adopting_str}"
            f"/{metric_key.plane.name}"
            f"/{metric_key.outcome.name}.png"
        ).replace(" ", "")
        as_cls_rows_dict = defaultdict(list)
        for row in relevant_rows:
            # NOTE: CHANGED! We want to display all the policies on the same graph
            # in a way that would break normal graphing
            # as_cls_rows_dict[row["metric_key"].scenario_config.AdoptPolicyCls].append(row)
            as_cls_rows_dict[row["metric_key"].PolicyCls].append(row)

        matplotlib.use("Agg")
        fig, ax = plt.subplots()
        fig.set_dpi(300)
        # Set X and Y axis size
        plt.xlim(0, self.x_limit)
        plt.ylim(0, self.y_limit)

        def get_percent_adopt(graph_row) -> float:
            """Extractions percent adoption for sort comparison

            Need separate function for mypy puposes
            """

            percent_adopt = graph_row["data_key"].percent_adopt
            assert isinstance(percent_adopt, (float, SpecialPercentAdoptions))
            return float(percent_adopt)

        # Add the data from the lines
        for i, (as_cls, graph_rows) in enumerate(as_cls_rows_dict.items()):
            graph_rows_sorted = list(sorted(graph_rows, key=get_percent_adopt))
            # If no trial_data is present for a selection, value can be None
            # For example, if no stubs are selected to adopt, the graph for adopting
            # stub ASes will have no data points
            # This is proper, rather than defaulting to 0 or 100, which causes problems
            graph_rows_sorted = [x for x in graph_rows_sorted if x["value"] is not None]
            ax.errorbar(
                [float(x["data_key"].percent_adopt) * 100 for x in graph_rows_sorted],
                [x["value"] for x in graph_rows_sorted],
                yerr=[x["yerr"] for x in graph_rows_sorted],
                label=self.label_replacement_dict.get(as_cls.name, as_cls.name),
                ls=self.line_styles[i],
                marker=self.markers[i],
            )
        # Set labels
        default_y_label = f"PERCENT {metric_key.outcome.name}".replace("_", " ")
        y_label = self.y_axis_label_replacement_dict.get(
            default_y_label, default_y_label
        )
        ax.set_ylabel(y_label)

        default_x_label = "Percent Adoption"
        x_label = self.x_axis_label_replacement_dict.get(
            default_x_label, default_x_label
        )
        ax.set_xlabel(x_label)

        # This is to avoid warnings
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, labels)
        plt.tight_layout()
        plt.rcParams.update({"font.size": 14, "lines.markersize": 10})
        (self.graph_dir / graph_name).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(self.graph_dir / graph_name)
        # https://stackoverflow.com/a/33343289/8903959
        ax.cla()
        plt.cla()
        plt.clf()
        # If you just close the fig, on machines with many CPUs and trials,
        # there is some sort of a memory leak that occurs. See stackoverflow
        # comment above
        plt.close(fig)
        # If you are running one simulation after the other, matplotlib
        # basically leaks memory. I couldn't find the original issue, but
        # here is a note in one of their releases saying to just call the garbage
        # collector: https://matplotlib.org/stable/users/prev_whats_new/
        # whats_new_3.6.0.html#garbage-collection-is-no-longer-run-on-figure-close
        # and here is the stackoverflow post on this topic:
        # https://stackoverflow.com/a/33343289/8903959
        # Even if this works without garbage collection in 3.5.2, that will break
        # as soon as we upgrade to the latest matplotlib which no longer does
        # If you run the simulations on a machine with many cores and lots of trials,
        # this bug leaks enough memory to crash the server, so we must garbage collect
        gc.collect()