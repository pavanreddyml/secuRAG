import requests
import jmespath
from jmespath.exceptions import JMESPathError

from . import Filter
from typing import Any, Dict, Optional


class HTTPRequestFilter(Filter):
    def __init__(
        self,
        name: str,
        url: str,
        query_field: str,
        method: str = "POST",
        headers: Optional[Dict[str, Any]] = None,
        timeout: int | float = 10,
        addn_fields: Optional[Dict[str, Any]] = None,
        scoring_field: Optional[str] = None,   # JMESPath expression
        logs_field: Optional[str] = None,      # JMESPath expression
        flagging_field: Optional[str] = None,  # JMESPath expression
        flagging_thresh: Optional[float] = None,
        inverted_thresh: bool = False,
        default_flag_on_fail: bool = True,
        default_flagged_response: str = "The query was flagged.",
        description: str = "",
        audit: bool = False,
    ) -> None:
        super().__init__(name=name, description=description, audit=audit, default_flagged_response=default_flagged_response)
        self.url = url
        self.method = method.upper()
        self.headers = self._validate_headers(headers)
        if self.method == "POST" and "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"
        self.timeout = timeout
        self.query_field = query_field
        self.addn_fields = addn_fields or {}
        if not isinstance(self.addn_fields, dict):
            raise TypeError("addn_fields must be a dict")
        if self.query_field in self.addn_fields:
            self.addn_fields.pop(self.query_field)

        # Keep raw strings (optional)
        self.scoring_field = scoring_field
        self.logs_field = logs_field
        self.flagging_field = flagging_field

        # Validate & compile JMESPath expressions at init (raises early if invalid)
        self._scoring_expr = self._compile_expr(scoring_field, "scoring_field")
        self._logs_expr = self._compile_expr(logs_field, "logs_field")
        self._flagging_expr = self._compile_expr(flagging_field, "flagging_field")

        self.flagging_thresh = flagging_thresh
        self.inverted_thresh = inverted_thresh
        self.default_flag_on_fail = default_flag_on_fail

    def _compile_expr(self, expr: Optional[str], field_name: str):
        """
        Validate and compile a JMESPath expression.
        Returns a compiled expression or None if expr is falsy/blank.
        Raises ValueError if the expression is syntactically invalid.
        """
        if expr is None:
            return None
        s = str(expr).strip()
        if not s:
            return None
        try:
            return jmespath.compile(s)
        except JMESPathError as e:
            raise ValueError(f"Invalid JMESPath for {field_name}: {expr!r}. {e}") from e

    def _validate_headers(self, headers):
        if headers is None:
            return {}
        if not isinstance(headers, dict):
            raise TypeError("headers must be a dict")
        validated = {}
        for k, v in headers.items():
            if k is None or v is None:
                continue
            if not isinstance(k, str):
                raise TypeError("header keys must be strings")
            ks = k.strip()
            vs = str(v).strip()
            if not ks:
                continue
            if any(c in ks for c in ("\r", "\n")) or any(c in vs for c in ("\r", "\n")):
                raise ValueError("header keys/values must not contain CR/LF characters")
            validated[ks] = vs
        return validated

    def _extract(self, data: Any, compiled_expr) -> Any:
        """
        Evaluate a pre-compiled JMESPath expression against `data`.
        Returns None if the expression is None, invalid at runtime, or yields no result.

        Note:
        - Standard JMESPath semantics already return None for missing paths (e.g., a.b on {}).
        - Filters that match nothing often yield [] which is a valid (empty) result; we keep it.
          If you want [] to be normalized to None, uncomment the block below.
        """
        if compiled_expr is None:
            return None
        try:
            result = compiled_expr.search(data)
        except JMESPathError:
            return None

        # Normalize truly "missing" to None; leave [] / {} as-is (they are valid results).
        # If you prefer [] -> None normalization, uncomment:
        # if result == []:
        #     return None

        return result

    def _to_float(self, v):
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v.strip())
            except Exception:
                return None
        return None

    def _to_bool(self, v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {"true", "t", "yes", "y", "1"}:
                return True
            if s in {"false", "f", "no", "n", "0"}:
                return False
        return None

    def run(self, query):
        used_threshold = False
        flag_value = None
        logs_value = {}
        status_code = None
        resp_json = None

        if self.method == "GET":
            params = {self.query_field: query}
            if self.addn_fields:
                params.update(self.addn_fields)
            resp = requests.get(self.url, params=params, headers=self.headers, timeout=self.timeout)
        else:
            payload = {self.query_field: query}
            if self.addn_fields:
                payload.update(self.addn_fields)
            resp = requests.post(self.url, json=payload, headers=self.headers, timeout=self.timeout)

        status_code = resp.status_code
        resp.raise_for_status()
        resp_json = resp.json()

        # Score (returns None if expression missing or yields non-numeric)
        if self._scoring_expr is not None:
            score_value = self._extract(resp_json, self._scoring_expr)
            sflt = self._to_float(score_value)
            self.set_score(sflt if sflt is not None else None)
        else:
            self.set_score(None)

        # Logs (if not a dict, wrap minimally)
        if self._logs_expr is not None:
            logs_value = self._extract(resp_json, self._logs_expr)
            logs_value = logs_value if logs_value is not None else {}
            if not isinstance(logs_value, dict):
                logs_value = {"logs_from_response": logs_value}

        # Flagging
        if self._flagging_expr is not None:
            flag_value = self._extract(resp_json, self._flagging_expr)
            parsed_bool = self._to_bool(flag_value)
            if parsed_bool is not None:
                self.set_flag(parsed_bool)
            else:
                if self.flagging_thresh is not None and self.get_score() is not None:
                    used_threshold = True
                    if self.inverted_thresh:
                        self.set_flag(self.get_score() < float(self.flagging_thresh))
                    else:
                        self.set_flag(self.get_score() > float(self.flagging_thresh))
                else:
                    self.set_flag(self.default_flag_on_fail)
        else:
            if self.flagging_thresh is not None and self.get_score() is not None:
                used_threshold = True
                if self.inverted_thresh:
                    self.set_flag(self.get_score() < float(self.flagging_thresh))
                else:
                    self.set_flag(self.get_score() > float(self.flagging_thresh))
            else:
                self.set_flag(self.default_flag_on_fail)

        audit_log = {
            "input": query,
            "output": query,
            "http_status": status_code,
            "score": self.get_score(),
            "flag": self.get_flag(),
            "flag_source": "score" if used_threshold else "response" if flag_value is not None else "default fallback",
        }

        audit_log = {
            **audit_log,
            **logs_value
        }

        self.log_audit(audit_log)
        return query