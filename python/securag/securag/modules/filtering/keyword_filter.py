from . import Filter


class KeywordFilter(Filter):
    def __init__(self, 
                 name, 
                 keywords, 
                 description="", 
                 audit=False, 
                 default_flagged_response="Cannot respond to query due to harmful keywords in the query."):
        super().__init__(name=name, description=description, audit=audit, default_flagged_response=default_flagged_response)
        self.keywords = keywords

    def run(self, query):
        identified = []

        matched = [keyword for keyword in self.keywords if keyword in query]
        if matched:
            identified.extend(matched)

        if len(identified) > 0:
            self.set_flag(True)

        audit_log = {
            "input": query,
            "output": query,
            "identified": identified,
        }

        self.log_audit(audit_log)

        return query

import re
from typing import Any, Dict, List, Optional

from . import Filter


class KeywordFilter(Filter):
    module_attributes = {"keywords_by_threshold", "stop_on_flag"}

    def __init__(
        self,
        name: str,
        keywords_by_threshold: Dict[int, List[str]],
        stop_on_flag: bool = True,
        description: str = "",
        audit: bool = False,
        default_flagged_response: str = "Query flagged by keyword policy.",
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            audit=audit,
            default_flagged_response=default_flagged_response,
        )

        if not isinstance(keywords_by_threshold, dict) or not keywords_by_threshold:
            raise ValueError("keywords_by_threshold must be a non-empty dict[int, list[str]].")

        # Validate thresholds and normalize lists
        for k, v in keywords_by_threshold.items():
            if not isinstance(k, int) or k < 1:
                raise ValueError("Threshold keys must be integers >= 1.")
            if not isinstance(v, list) or not all(isinstance(s, str) for s in v):
                raise TypeError(f"Value for threshold {k} must be a list[str].")

        self.keywords_by_threshold: Dict[int, List[str]] = keywords_by_threshold
        self.stop_on_flag: bool = bool(stop_on_flag)

        # Cached detail from last run for flagged_response()
        self._last_triggered: List[Dict[str, Any]] = []
        self._last_identified: Dict[int, List[str]] = {}

    def run(self, query: str) -> str:
        self._last_triggered = []
        self._last_identified = {}

        # Evaluate buckets in ascending threshold order
        for threshold in sorted(self.keywords_by_threshold.keys()):
            bucket = self.keywords_by_threshold[threshold]
            matched = [kw for kw in bucket if kw in query]
            # distinct matches (already deduped)
            count_distinct = len(matched)
            self._last_identified[threshold] = matched

            if count_distinct >= threshold:
                self.set_flag(True)
                self._last_triggered.append(
                    {"threshold": threshold, "count": count_distinct, "matched": matched}
                )
                if self.stop_on_flag:
                    break

        audit_log = {
            "input": query,
            "output": query,
            "identified": self._last_identified,
            "triggered": self._last_triggered,
            "stop_on_flag": self.stop_on_flag,
        }
        self.log_audit(audit_log)

        return query

    def flagged_response(self) -> str:
        if not self.get_flag():
            return ""
        # Prefer detailed message based on last run
        if self._last_triggered:
            parts = []
            for t in self._last_triggered:
                thr = t.get("threshold")
                cnt = t.get("count")
                matched = t.get("matched", [])
                parts.append(
                    f"Bucket {thr}: matched {cnt} keyword(s) "
                    + (f"[{', '.join(matched)}]" if matched else "")
                )
            detail = "; ".join(parts)
            return f"The query was flagged by keyword policy: {detail}."
        return self.default_flagged_response