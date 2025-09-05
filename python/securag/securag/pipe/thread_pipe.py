from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from typing import Literal

from securag.modules import Module
from . import Pipe


class ThreadPipe(Pipe):
    @property
    def pipe_type(self):
        return "ThreadPipe"

    def __init__(
        self,
        name: str,
        modules: list[Module],
        description: str = "",
        audit: bool = False,
        flagging_strategy: Literal["any", "all", "manual"] = "any",
        stop_on_flag: bool = True,
        max_workers: int | None = None,
    ):
        super().__init__(
            name=name,
            modules=modules,
            description=description,
            audit=audit,
            flagging_strategy=flagging_strategy,
        )
        self.stop_on_flag = stop_on_flag
        self.max_workers = max_workers

    def run(self, input_data):
        outputs: dict[str, object] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_module = {
                executor.submit(module, deepcopy(input_data)): module
                for module in self.modules
            }

            try:
                for future in as_completed(future_to_module):
                    module = future_to_module[future]
                    mod_name = module.get_name() if hasattr(module, "get_name") else type(module).__name__
                    try:
                        result = future.result()
                    except Exception:
                        self._force_set_flag(True)
                        result = input_data
                    outputs[mod_name] = result

                    self.set_flag()

                    if self.stop_on_flag and self.get_flag():
                        for f in future_to_module:
                            if f is not future and not f.done():
                                f.cancel()
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
            finally:
                for f in future_to_module:
                    if not f.done():
                        f.cancel()

        return input_data
