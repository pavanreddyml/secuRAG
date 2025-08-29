# ----------------------------------IMPORTS----------------------------------
import os
from securag.modules.filtering import KeywordFilter, HTTPRequestFilter
from securag.pipe import SequentialPipe, ThreadPipe
from securag.executor.executor import SecuRAGExecutor

# ----------------------------CREATE EXECUTOR HERE----------------------------

def create_executor() -> SecuRAGExecutor:
    # SAMPLE EXECUTOR CREATION CODE. MODIFY AS NEEDED.
    keywords = ["sensitive", "confidential", "top secret"]
    keywords2 = ["abcd"]

    filter_module = KeywordFilter("Filtering Module", keywords, audit=True)
    filter_module2 = KeywordFilter("Filtering Module 2", keywords2, audit=True)

    http_fil_mod = HTTPRequestFilter(
        name="PIA Classifier",
        url="https://router.huggingface.co/hf-inference/models/protectai/deberta-v3-base-prompt-injection-v2/",
        query_field="inputs",
        headers={"Authorization": f"Bearer {os.getenv('HF_AUTH_TOKEN')}", "content-type": "application/json"},
        timeout=5,
        scoring_field="[0][?label=='INJECTION'].score | [0]",
        logs_field=None,
        flagging_field=None,
        flagging_thresh=0.5,
        inverted_thresh=False,
        default_flag_on_fail=True,
        description="An HTTP filter module",
        audit=True,
    )

    http_fil_mod2 = HTTPRequestFilter(
        name="Content Filter",
        url="https://router.huggingface.co/hf-inference/models/s-nlp/roberta_toxicity_classifier/",
        query_field="inputs",
        headers={"Authorization": f"Bearer {os.getenv('HF_AUTH_TOKEN')}", "content-type": "application/json"},
        timeout=5,
        scoring_field="[0][?label=='toxic'].score | [0]",
        logs_field=None,
        flagging_field=None,
        flagging_thresh=0.5,
        inverted_thresh=False,
        default_flag_on_fail=True,
        description="An HTTP filter module",
        audit=True,
    )

    pipe = ThreadPipe("Filtering Pipe", [filter_module, filter_module2, http_fil_mod, http_fil_mod2],
                        audit=True, flagging_strategy="all", stop_on_flag=True, max_workers=5)

    executor = SecuRAGExecutor([pipe], raise_on_flag=False)

    executor.execute_inputs("This is a sensitive document. ")

    return executor

# -------------------------------DO NOT CHANGE--------------------------------

executor = create_executor()
if not isinstance(executor, SecuRAGExecutor):
    raise ValueError("The 'create_executor' function must return a SecuRAGExecutor instance.")

