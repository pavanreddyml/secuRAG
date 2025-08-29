import textwrap
from securag import pipe
from securag.pipe import Pipe

from copy import deepcopy

from securag.exceptions import FlaggedInputError, FlaggedOutputError

class SecuRAGExecutor:
    def __init__(self, 
                 input_pipes: list[Pipe] = None, 
                 output_pipes: list[Pipe] = None, 
                 raise_on_flag=True):
        self.input_pipes = input_pipes or []
        self.output_pipes = output_pipes or []
        self.raise_on_flag = raise_on_flag

        self.logs = []

        self._initialize_pipes()

    def execute_inputs(self, query: str):
        self.logs.clear()
        query_copy = deepcopy(query)
        for pipe in self.input_pipes:
            query_copy = pipe(query_copy)
            audit_logs = pipe.get_audit_logs()
            audit_logs['type'] = "input"
            self.logs.append(audit_logs)

            if pipe.get_flag() and self.raise_on_flag:
                raise FlaggedInputError(f"Input was flagged by Pipe: {pipe.get_name()}. Run print_logs() to see details.")
        return query_copy

    def execute_outputs(self, output: str):
        self.logs.clear()
        output_copy = deepcopy(output)
        for pipe in self.output_pipes:
            output_copy = pipe(output_copy)
            audit_logs = pipe.get_audit_logs()
            audit_logs['type'] = "output"
            self.logs.append(audit_logs)

            if pipe.get_flag() and self.raise_on_flag:
                raise FlaggedOutputError(f"Output was flagged by Pipe: {pipe.get_name()}. Run print_logs() to see details.")

        return output_copy
    
    
    def get_logs(self):
        return self.logs

    def print_logs(self):
        final_logs = ""
        skip_pipe = {'id','name','type','execution_time','flag','status','num_modules','log', 'modules'}
        skip_module = {'id','name','execution_time','flag','score','status','log'}
        for log in self.logs:
            pipe_logs = (
                f" PIPE {log.get('id')}: {log.get('name')} ".center(70, "-")
                + "\n"
                + "\n".join(
                    [
                        f"Type: {log.get('type')}",
                        f"Execution Time: {log.get('execution_time')}",
                        f"Flag: {log.get('flag')}",
                        f"Status: {log.get('status')}",
                        f"Num Modules: {len(log.get('modules') or [])}",
                        *[
                            f"{k.title()}: "
                            + textwrap.fill(
                                str(v),
                                width=100,
                                subsequent_indent=" " * (len(k) + 6),
                            )
                            for k, v in log.items() if k not in skip_pipe
                        ],
                        f"Logs: ",
                    ]
                )
            )

            for k, v in log.get('log', {}).items():
                wrapped_value = textwrap.fill(str(v), width=100, subsequent_indent=" " * (len(k) + 6))
                pipe_logs += f"\n{' ' * 4}{k}: {wrapped_value}"

            final_logs += pipe_logs + "\n"


            for module in log.get('modules', []):
                    module_logs = (
                        f"\n{' ' * 4}"
                        + f" MODULE {module.get('id')}: {module.get('name')} ".center(50, "-")
                        + "\n"
                        + "\n".join(
                            [
                                f"{' ' * 4}Execution Time: {module.get('execution_time')}",
                                f"{' ' * 4}Flag: {module.get('flag')}",
                                f"{' ' * 4}Score: {module.get('score')}",
                                f"{' ' * 4}Status: {module.get('status')}",
                                *[
                                    f"{' ' * 4}{k.title()}: "
                                    + textwrap.fill(
                                        str(v),
                                        width=100,
                                        subsequent_indent=" " * (len(k) + 8),
                                    )
                                    for k, v in module.items() if k not in skip_module
                                ],
                                f"{' ' * 4}Logs:",
                            ]
                        )
                    )

                    for k, v in module.get('log', {}).items():
                        wrapped_value = textwrap.fill(str(v), width=100, subsequent_indent=" " * (len(k) + 10))
                        module_logs += f"\n{' ' * 8}{k}: {wrapped_value}"

                    final_logs += module_logs + "\n"

        print(final_logs)


    def _initialize_pipes(self):
        for i, pipe in enumerate(self.input_pipes + self.output_pipes):
            pipe.assign_id(i+1)
            pipe.initialize_modules()
            pipe.reset()
