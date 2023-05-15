#
#       Another volatility plugin.
#       - rikitik. and those who know, know!
# 
import datetime
import logging
import os
from typing import Generator, Iterable , List, Tuple, Optional, Callable

from volatility3.framework import interfaces, renderers, layers, constants, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, psscan

vollog = logging.getLogger(__name__)


class UnlinkedProcessScanner(interfaces.plugins.PluginInterface):
    """
    Scans for processes unlinked from psActiveProcessList.
    """

    # cuz installed Framework interface version 2
    _required_framework_version = (2, 0, 0)     

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="psscan", plugin=psscan.PsScan, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Display physical offset instead of virtual",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only_susp",
                description="Display only potentially suspicious processes, but with \
greater verbosity",
                default=False,
                optional=True,
            )
        ]

    def _generator (self,):
        kernel = self.context.modules[self.config["kernel"]]
        memory = self.context.layers[kernel.layer_name]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        # creating a list of "known" pid's.
        psActiveProcessList_pids = []
        for task in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        ):
            psActiveProcessList_pids.append(task.UniqueProcessId)

        # scanning memory for EProcess strcutures.
        # comparing findings to "known" pid's to find processes potentially unlinked 
        # from PsActiveProcessList
        for proc in psscan.PsScan.scan_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            #filter_func=filter_func,
        ):

            process_is_kinda_susp = False

            # VALIDATIONS:
            # -
            # 1) validation with psActiveProcessList by PID
            in_psActiveProcessList = True
            if not proc.UniqueProcessId in psActiveProcessList_pids:
                in_psActiveProcessList = False
                process_is_kinda_susp = True
            
            # /END VALIDATIONS

            # BEFORE YIELDING NEXT ITERRABLE:
            # -
            # option- offset correction
            if not self.config["physical"]:
                offset = proc.vol.offset
            else:
                (_, _, offset, _, _) = list(
                    memory.mapping(offset=proc.vol.offset, length=0)
                )[0]

            try:
                if self.config["only_susp"]:
                    if process_is_kinda_susp:
                        yield (
                            0,
                            (
                                proc.UniqueProcessId,
                                proc.InheritedFromUniqueProcessId,
                                proc.ImageFileName.cast(
                                    "string",
                                    max_length=proc.ImageFileName.vol.count,
                                    errors="replace",
                                ),
                                format_hints.Hex(offset),
                                proc.ActiveThreads,
                                proc.get_handle_count(),
                                proc.get_session_id(),
                                proc.get_is_wow64(),
                                proc.get_create_time(),
                                proc.get_exit_time(),
                            ),
                        )
                else:
                    yield (
                        0,
                        (
                            proc.UniqueProcessId,
                            proc.ImageFileName.cast(
                                "string",
                                max_length=proc.ImageFileName.vol.count,
                                errors="replace",
                            ),
                            format_hints.Hex(offset),
                            in_psActiveProcessList,
                        ),
                    )
            except exceptions.InvalidAddressException:
                vollog.info(
                    f"Invalid process found at address: {proc.vol.offset:x}. Skipping"
                )

    def run (self,):
        offsettype = "(V)" if not self.config["physical"] else "(P)"
        if self.config["only_susp"]:
            return renderers.TreeGrid(
                [
                    ("PID", int),
                    ("PPID", int),
                    ("ImageFileName", str),
                    (f"Offset{offsettype}", format_hints.Hex),
                    ("Threads", int),
                    ("Handles", int),
                    ("SessionId", int),
                    ("Wow64", bool),
                    ("CreateTime", datetime.datetime),
                    ("ExitTime", datetime.datetime),
                ],
                self._generator(),
            )#("In_psActiveProcessList", bool),  -> maybe add this row if add validations will be made in more ways than one.
        else:
            return renderers.TreeGrid(
                [
                    ("PID", int),
                    ("ImageFileName", str),
                    (f"Offset{offsettype}", format_hints.Hex),
                    ("In_psActiveProcessList", bool),
                ],
                self._generator(),
        )
