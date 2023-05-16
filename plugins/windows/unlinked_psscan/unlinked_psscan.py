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
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, psscan, handles

vollog = logging.getLogger(__name__)


class Unlinked_PsScan(interfaces.plugins.PluginInterface):
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
    
    @classmethod
    def get_known_pids_psActiveProcessList(
        cls,
        _context: interfaces.context.ContextInterface,
        _layer_name: str,
        _symbol_table: str,
    ) -> list:
        """
        returns a list of PIDs (integers) of processes listed in psActiveProcessList.
        (filtering output of windows.pslist.PsList plugin)

        Args:
            - relevant args for pslist.PsList.list_processes.
        """
        pids_list = []
        for proc in pslist.PsList.list_processes(
            context=_context,
            layer_name=_layer_name,
            symbol_table=_symbol_table,
        ):
            pids_list.append(proc.UniqueProcessId)
        return pids_list
    
    @classmethod
    def get_known_pids_systemProcessHandles(
        cls,
        _context: interfaces.context.ContextInterface,
        _layer_name: str,
        _symbol_table: str,
        _config_path,
    ) -> list:
        """
        returns a list of PIDs (integers) of processes that system process has 
        handles to.

        Args:
            - relevant args for pslist.PsList.list_processes.
            - 'config_path' for handles.Handles.
        """
        pids_list = []
        
        # acquiring handle table of system process from its _EProcess structure
        try:
            # this must only yield one result.
            system_process = next(pslist.PsList.list_processes(
                context=_context,
                layer_name=_layer_name,
                symbol_table=_symbol_table,
                filter_func=pslist.PsList.create_pid_filter(pid_list=[4,])
            ))
            system_process_handle_table = system_process.ObjectTable
        except StopIteration as e:
            vollog.info(
                f"Could not find system process (pid 4) in process list. - Skipping handles check."
            )
        except exceptions.InvalidAddressException:
            vollog.log(
                f"Could not access system process (pid 4) _EPROCESS.ObjectType. - Skipping handles check."
            )
        
        # preparing windows.handles.Handles plugin for enumerating previously acquired 
        # handle table of system process.
        h_instance = handles.Handles(context=_context, config_path=_config_path)
        type_map = handles.Handles.get_type_map(
            context=_context,
            layer_name=_layer_name,
            symbol_table=_symbol_table,
        )
        cookie = handles.Handles.find_cookie(
            context=_context,
            layer_name=_layer_name,
            symbol_table=_symbol_table,
        )
        
        # finally, enumerating pids of processes from system process handles
        for entry in h_instance.handles(
            handle_table=system_process_handle_table
            ):
            obj_type = entry.get_object_type(type_map, cookie)
            if obj_type == "Process":
                item = entry.Body.cast("_EPROCESS")
                pids_list.append(item.UniqueProcessId)
                #obj_name = f"{utility.array_to_string(item.ImageFileName)} Pid {item.UniqueProcessId}"

        return pids_list
    

    def _generator (self,):
        kernel = self.context.modules[self.config["kernel"]]
        memory = self.context.layers[kernel.layer_name]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        # creating list of "known" pids, using various methods of discovery.
        # -
        # 1) extracting pids of _EProcess structures in psActiveProcessList
        psActiveProcessList_pids    = self.get_known_pids_psActiveProcessList(
            _context=self.context,
            _layer_name=kernel.layer_name,
            _symbol_table=kernel.symbol_table_name,
        )
        # 2) extracting pids of handles to processes (_EProcess structures) from system.exe process (pid 4)
        systemProcHandleList_pids   = self.get_known_pids_systemProcessHandles(
            _context=self.context,
            _layer_name=kernel.layer_name,
            _symbol_table=kernel.symbol_table_name,
            _config_path=self.config_path
        )

        # scanning memory for EProcess strcutures.
        # comparing findings to "known" pid's to find processes potentially unlinked 
        # from PsActiveProcessList
        for proc in psscan.PsScan.scan_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            #filter_func=filter_func,
        ):

            in_psActiveProcessList  = True
            in_systemProcessHandles = True
            
            # COMPARISON METHODS:
            # -
            # 1) validation with psActiveProcessList by PID
            if not proc.UniqueProcessId in psActiveProcessList_pids:
                in_psActiveProcessList  = False

            # 2) validating with system process handles by PID
            if not proc.UniqueProcessId in systemProcHandleList_pids:
                in_systemProcessHandles = False
            
            # so, is the process suspicious?
            process_is_kinda_susp = not in_psActiveProcessList or \
                                    not in_systemProcessHandles

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
                            in_systemProcessHandles,
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
                    ("InpsActiveProcessList", bool),
                    ("inSystemProcessHandles", bool),
                ],
                self._generator(),
        )
