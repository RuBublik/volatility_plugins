#
#       my custom volatility plugin for testing
#       - rikitik. and those who know, know!
# 
from typing import Callable, List, Generator, Iterable, Type, Optional

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins


class Rikitik(plugins.PluginInterface):
    """Test Plugin"""
    _required_framework_version = (2, 0, 0)     # cuz installed Framework interface version 2
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return []
    
    def run (self):
        #kernel = self.context.modules[self.config["kernel"]]
        return renderers.TreeGrid(
            [
                ("Hello_World", str),
            ], None
        )

    def _generator(self, data):
        pass