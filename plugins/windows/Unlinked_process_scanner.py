#
#       Another volatility plugin.
#       - rikitik. and those who know, know!
# 
import logging
import os
from typing import List

from volatility3.framework import interfaces, renderers, constants, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import poolscanner, pslist

vollog = logging.getLogger(__name__)

class UnlinkedProcessScanner(plugins.PluginInterface):
    """
    Scans for processes unlinked from psActiveProcessList.
    
    In normal operation, the psActiveProcessList is a doubly linked list of all
    active processes in the system. If a process has been unlinked from this
    list, it may indicate malicious activity, such as an attempt to hide the
    process from system monitoring tools.
    
    This plugin performs a scan of Ethread strcuture pool tags of running threads,
    creating a list of active processes (with at least one active thread). Then,
    compares the list to psActiveProcessList to find processes that have been unlinked.
    Any such processes are reported as potentially suspicious.
    
    Note that there may be legitimate reasons for a process to be unlinked from
    the process list, such as during the process creation or termination
    phases. Therefore, this plugin should be used as one tool among many for
    detecting malicious activity, and its results should be interpreted in the
    context of other system monitoring and analysis tools.
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
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
        ]
    
    def run (self):
        return renderers.TreeGrid(
            [
                ("PROC_ID", int),
                ("PROC_LAYER_NAME", str),
            ],
            self._generator(),
        )

    def _generator(self, data):
        kernel = self.context.modules[self.config["kernel"]]
        
        for task in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            #filter_func=filter_func,
        ):
            proc_id = "Unknown"
            try:
                proc_id = task.UniqueProcessId
                proc_layer_name = task.add_process_layer()
                yield (
                    0,
                    (
                        proc_id,
                        proc_layer_name,
                    ),
                )
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )
                continue

