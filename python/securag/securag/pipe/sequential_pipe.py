from . import Pipe

from typing import Literal


class SequentialPipe(Pipe):
    @property
    def pipe_type(self):
        return "SequentialPipe"

    def __init__(self,
                 name,
                 modules,
                 description="",
                 audit=False, 
                 flagging_strategy: Literal["any", "all", "manual"] = "any",
                 stop_on_flag=True
                 ):
        super().__init__(name=name, 
                         modules=modules, 
                         description=description, 
                         audit=audit, 
                         flagging_strategy=flagging_strategy)
        self.stop_on_flag = stop_on_flag

    def run(self, input_data):
        for module in self.modules:
            input_data = module(input_data)
            self.set_flag()
            if self.stop_on_flag and self.get_flag():
                break
        return input_data