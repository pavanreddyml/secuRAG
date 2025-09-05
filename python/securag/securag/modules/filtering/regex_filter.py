import re
from typing import Any, Dict, List

from . import Filter


class RegexFilter(Filter):
    def __init__(
        self,
        name: str,
        patterns_by_threshold: Dict[int, List[str]],
        stop_on_flag: bool = True,
        regex_flags: int = 0,
        description: str = "",
        audit: bool = False,
        default_flagged_response: str = "Query flagged by regex policy.",
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            audit=audit,
            default_flagged_response=default_flagged_response,
        )

        if not isinstance(patterns_by_threshold, dict) or not patterns_by_threshold:
            raise ValueError("patterns_by_threshold must be a non-empty dict[int, list[str]].")

        # Validate thresholds and patterns, and precompile
        self._compiled_by_threshold: Dict[int, List[re.Pattern]] = {}
        self._src_by_threshold: Dict[int, List[str]] = {}
        for k, v in patterns_by_threshold.items():
            if not isinstance(k, int) or k < 1:
                raise ValueError("Threshold keys must be integers >= 1.")
            if not isinstance(v, list) or not all(isinstance(p, str) for p in v):
                raise TypeError(f"Value for threshold {k} must be a list[str] of regex patterns.")

            compiled_list: List[re.Pattern] = []
            for p in v:
                try:
                    compiled_list.append(re.compile(p, regex_flags))
                except re.error as e:
                    raise ValueError(f"Invalid regex at threshold {k}: {p!r}. {e}") from e

            self._compiled_by_threshold[k] = compiled_list
            self._src_by_threshold[k] = v

        self.stop_on_flag: bool = bool(stop_on_flag)
        self.regex_flags: int = int(regex_flags)

        # Cached detail from last run for flagged_response()
        self._last_triggered: List[Dict[str, Any]] = []
        self._last_identified: Dict[int, List[str]] = {}

    def run(self, query: str) -> str:
        self._last_triggered = []
        self._last_identified = {}

        # Evaluate buckets in ascending threshold order
        for threshold in sorted(self._compiled_by_threshold.keys()):
            compiled_bucket = self._compiled_by_threshold[threshold]
            src_bucket = self._src_by_threshold[threshold]

            matched_src: List[str] = []
            for patt, src in zip(compiled_bucket, src_bucket):
                # patt is precompiled, so no runtime compile errors expected
                if patt.search(query) is not None:
                    matched_src.append(src)

            self._last_identified[threshold] = matched_src

            if len(matched_src) >= threshold:
                self.set_flag(True)
                self._last_triggered.append(
                    {"threshold": threshold, "count": len(matched_src), "matched": matched_src}
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
        if self._last_triggered:
            parts = []
            for t in self._last_triggered:
                thr = t.get("threshold")
                cnt = t.get("count")
                matched = t.get("matched", [])
                parts.append(
                    f"Bucket {thr}: matched {cnt} pattern(s) "
                    + (f"[{', '.join(matched)}]" if matched else "")
                )
            detail = "; ".join(parts)
            return f"The query was flagged by regex policy: {detail}."
        return self.default_flagged_response
