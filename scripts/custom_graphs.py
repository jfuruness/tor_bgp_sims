from collections import defaultdict
from functools import cached_property
from itertools import product
from pathlib import Path
import pickle

import matplotlib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore

from bgpy.simulation_framework.metric_tracker.metric_key import MetricKey
from bgpy.simulation_framework.utils import get_all_metric_keys

from bgpy.enums import SpecialPercentAdoptions, Outcomes, ASGroups, Plane


class CombinedGraph:
    """Automates graphing of default graphs"""

    def __init__(self, pickle_path_1: Path, self.pickle_path_2: Path, graph_dir: Path) -> None:
        self.pickle_path_1: Path = pickle_path_1
        with self.pickle_path_1.open("rb") as f:
            self.graph_rows_1 = pickle.load(f)
        self.pickle_path_2: Path = pickle_path_2
        with self.pickle_path_2.open("rb") as f:
            self.graph_rows_2 = pickle.load(f)

        self.graph_dir: Path = graph_dir
        self.graph_dir.mkdir(parents=True, exist_ok=True)

    def __init__(
        self,
        pickle_path_1: Path,
        pickle_path_2: Path,
        graph_dir: Path,
        # A nice way to substitute labels post run
        label_replacement_dict=None,
        y_axis_label_replacement_dict=None,
        x_axis_label_replacement_dict=None,
        x_limit: int = 100,
        y_limit: int = 100,
        metric_keys: tuple[MetricKey, ...] = tuple(list(get_all_metric_keys())),
    ) -> None:
        self.pickle_path_1: Path = pickle_path_1
        with self.pickle_path_1.open("rb") as f:
            self.graph_rows_1 = pickle.load(f)
            max_prop_round = max(
                x["data_key"].propagation_round for x in self.graph_rows_1
            )
            self.graph_rows_1 = [
                x
                for x in self.graph_rows_1
                if x["data_key"].propagation_round == max_prop_round
            ]
        self.pickle_path_2: Path = pickle_path_2
        with self.pickle_path_2.open("rb") as f:
            self.graph_rows_2 = pickle.load(f)
            max_prop_round = max(
                x["data_key"].propagation_round for x in self.graph_rows_2
            )
            self.graph_rows_2 = [
                x
                for x in self.graph_rows_2
                if x["data_key"].propagation_round == max_prop_round
            ]

        self.graph_dir: Path = graph_dir
        self.graph_dir.mkdir(parents=True, exist_ok=True)

        if label_replacement_dict is None:
            label_replacement_dict = dict()
        self.label_replacement_dict = label_replacement_dict

        if x_axis_label_replacement_dict is None:
            x_axis_label_replacement_dict = dict()
        self.x_axis_label_replacement_dict = x_axis_label_replacement_dict

        if y_axis_label_replacement_dict is None:
            y_axis_label_replacement_dict = dict()
        self.y_axis_label_replacement_dict = y_axis_label_replacement_dict
        self.x_limit = x_limit
        self.y_limit = y_limit

        self.metric_keys: tuple[MetricKey, ...] = metric_keys


    def generate_graphs(self) -> None:
        """Generates default graphs"""

        # Each metric key here contains plane, as group, and outcome
        # In other words, aech type of graph

        graph_infos = list(product(self.metric_keys, [True, False, Any]))

        for metric_key, adopting in tqdm(
            graph_infos, total=len(graph_infos), desc="Writing Graphs"
        ):
            relevant_rows = [[], []]
            for i, graph_rows in enumerate([self.graph_rows_1, self.graph_rows_2])
                for row in graph_rows:
                    # Get all the rows that correspond to that type of graph
                    BasePolicyCls = row["data_key"].scenario_config.BasePolicyCls
                    AdoptPolicyCls = row["data_key"].scenario_config.AdoptPolicyCls
                    if (
                        row["metric_key"].plane == metric_key.plane
                        and row["metric_key"].as_group == metric_key.as_group
                        and row["metric_key"].outcome == metric_key.outcome
                        and (
                            (
                                row["metric_key"].PolicyCls == BasePolicyCls
                                and adopting is False
                            )
                            or (
                                row["metric_key"].PolicyCls == AdoptPolicyCls
                                and adopting is True
                            )
                            or (row["metric_key"].PolicyCls == Policy and adopting is Any)
                        )
                    ):
                        relevant_rows[i].append(row)

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

        if not relevant_rows[0] and not relevant_rows[1]:
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
        as_cls_rows_dicts = [defaultdict(list), defaultdict(list)]
        for i, relevant_row_list in enumerate(relevant_rows):
            for row in relevant_row_list:
                as_cls_rows_dicts[i][row["data_key"].scenario_config.AdoptPolicyCls].append(row)

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
        for i, ((as_cls_1, graph_rows_1), (as_cls_2, graph_rows_2)) in enumerate(zip(as_cls_rows_dicts[0].items(), as_cls_rows_dicts[1].items())):
            graph_rows_1_sorted = list(sorted(graph_rows_1, key=get_percent_adopt))
            graph_rows_2_sorted = list(sorted(graph_rows_2, key=get_percent_adopt))
            # If no trial_data is present for a selection, value can be None
            # For example, if no stubs are selected to adopt, the graph for adopting
            # stub ASes will have no data points
            # This is proper, rather than defaulting to 0 or 100, which causes problems
            graph_rows_1_sorted = [x for x in graph_rows_1_sorted if x["value"] is not None]
            graph_rows_2_sorted = [x for x in graph_rows_2_sorted if x["value"] is not None]
            assert as_cls_1 == as_cls_2, "These must not be lining up?"
            ax.errorbar(
                [float(x["data_key"].percent_adopt) * 100 for x in graph_rows_sorted],
                [x1["value"] * x2["value"] / 100 for x1, x2 in zip(graph_rows_1_sorted, graph_rows_2_sorted)],
                # Not going to bother with the math here, since error bars are
                # already not even visible for the individual graphs
                # with the amount of trials we run
                # It's a shortcut, but this is a one off for paper results, so it's fine
                yerr=[0 for x in graph_rows_sorted],
                label=self.label_replacement_dict.get(as_cls_1.name, as_cls_1.name),
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

    @cached_property
    def markers(self) -> tuple[str, ...]:
        # Leaving this as a list here for mypy
        markers = [".", "1", "*", "x", "d", "2", "3", "4"]
        markers += markers.copy()[0:-2:2]
        markers += markers.copy()[::-1]
        return tuple(markers)

    @cached_property
    def line_styles(self) -> tuple[str, ...]:
        # Leaving this as a list here for mypy
        styles = ["-", "--", "-.", ":", "solid", "dotted", "dashdot", "dashed"]
        styles += styles.copy()[::-1]
        styles += styles.copy()[0:-2:2]
        return tuple(styles)



if __name__ == "__main__":
    BASE_DIR = Path.home() / "Desktop" / "aws_tor_sims" / "tor"
    paths = [
        [
            BASE_DIR / "client_to_guard_mh" / "data.pickle",
            BASE_DIR / "exit_to_dest_mh" / "data.pickle",
            BASE_DIR / "guard_and_exit",
        ],
        [
            BASE_DIR / "client_to_guard_us_mh" / "data.pickle",
            BASE_DIR / "exit_to_dest_us_mh" / "data.pickle",
            BASE_DIR / "guard_and_exit_us",

        ]
    ]
    for pickle_path_1, pickle_path_2, graph_dir in paths:
        CombinedGraph(
            pickle_path_1=pickle_path_1,
            pickle_path_2=pickle_path_2,
            graph_dir=graph_dir,
        ).generate_graphs()
