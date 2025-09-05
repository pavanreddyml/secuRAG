import os
import re
import json
import uuid
import time
import logging
import traceback
from datetime import datetime
from pathlib import Path

from securag.executor import SecuRAGExecutor
from securag.exceptions import FlaggedInputError, FlaggedOutputError
from modules.executor import executor
from modules.ai_response import ai_response, AIResponse

from flask import Flask, request, jsonify, make_response
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.pool import NullPool
from sqlalchemy import event

# -------------------- SET ENV (example defaults) --------------------
from dotenv import load_dotenv
load_dotenv(r"C:\Users\Pavan Reddy\Desktop\secuRAG\.env")

# -------------------- LOGGING --------------------
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("securag.flask")


class SecuRAGServer:
    SECURAG_SERVER_DB_URI = os.getenv("SECURAG_SERVER_DB_URI", "").strip()
    SECURAG_SERVER_TABLE_NAME = os.getenv("SECURAG_SERVER_TABLE_NAME", "audit_log").strip()
    SECURAG_SERVER_WRITE_LOGS = os.getenv("SECURAG_SERVER_WRITE_LOGS", "false").strip().lower() == "true"

    def __init__(self, 
                 name: str, 
                 executor: SecuRAGExecutor=None, 
                 ai_response: AIResponse=None):
        self.app = Flask(name)

        if not isinstance(executor, SecuRAGExecutor):
            raise TypeError("executor must be of type SecuRAGExecutor")
        self.executor = executor

        if not isinstance(ai_response, AIResponse):
            raise TypeError("ai_response must be of type AIResponse")
        self.ai_response = ai_response

        self.engine: Engine | None = None

        if self.SECURAG_SERVER_WRITE_LOGS:
            self._initialize_db()

        self._setup_routes()

    # -------------------- DB INIT & VALIDATION --------------------
    def _normalize_db_uri(self, uri: str) -> str:
        if "://" in uri:
            return uri
        p = Path(uri).expanduser().resolve()
        path_str = str(p).replace("\\", "/")
        return f"sqlite:///{path_str}"
    
    def _safe_table_name(self, name: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RuntimeError("Invalid table name")
        return name

    def _initialize_db(self):
        if not self.SECURAG_SERVER_DB_URI:
            raise RuntimeError("SECURAG_SERVER_WRITE_LOGS is True but SECURAG_SERVER_DB_URI is empty")

        db_uri = self._normalize_db_uri(self.SECURAG_SERVER_DB_URI)
        logger.debug("Using DB URI: %s", db_uri)

        connect_args = {}
        if db_uri.startswith("sqlite:///"):
            connect_args = {"check_same_thread": False}

        try:
            self.engine = create_engine(
                db_uri,
                future=True,
                pool_pre_ping=True,
                poolclass=NullPool,  # close connections ASAP; reduces lock contention
                connect_args={"check_same_thread": False, "timeout": 30}
            )

            if db_uri.startswith("sqlite:///"):
                @event.listens_for(self.engine, "connect")
                def _set_sqlite_pragma(dbapi_conn, _):
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA journal_mode=WAL;")
                    cur.execute("PRAGMA synchronous=NORMAL;")
                    cur.close()
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except SQLAlchemyError as e:
            raise RuntimeError(f"Database connection failed: {e}") from e

        table = self._safe_table_name(self.SECURAG_SERVER_TABLE_NAME)
        dialect = self.engine.dialect.name

        with self.engine.begin() as conn:
            exists = False
            if dialect == "sqlite":
                q = text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t")
                exists = conn.execute(q, {"t": table}).scalar() is not None
            elif dialect in ("postgresql", "postgres"):
                q = text("SELECT to_regclass(:t)")
                exists = conn.execute(q, {"t": table}).scalar() is not None
            else:
                q = text("SELECT 1 FROM information_schema.tables WHERE table_name=:t")
                exists = conn.execute(q, {"t": table}).first() is not None

            if not exists:
                if dialect == "sqlite":
                    ddl = f"""
                    CREATE TABLE {table} (
                        uuid TEXT PRIMARY KEY,
                        message_id TEXT NOT NULL,
                        content TEXT NOT NULL,
                        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                    idx = f"CREATE INDEX IF NOT EXISTS idx_{table}_message_id ON {table}(message_id)"
                elif dialect in ("postgresql", "postgres"):
                    ddl = f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                        uuid VARCHAR(36) PRIMARY KEY,
                        message_id TEXT NOT NULL,
                        content JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                    idx = f"CREATE INDEX IF NOT EXISTS idx_{table}_message_id ON {table}(message_id)"
                else:
                    ddl = f"""
                    CREATE TABLE {table} (
                        uuid VARCHAR(36) PRIMARY KEY,
                        message_id VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL
                    )
                    """
                    idx = f"CREATE INDEX idx_{table}_message_id ON {table}(message_id)"
                conn.execute(text(ddl))
                conn.execute(text(idx))
                logger.info("Created table '%s' (uuid PK) and index on message_id.", table)
            else:
                self._validate_schema(conn, table, dialect)

        logger.info("Database and table schema validated/created successfully.")

    def _validate_schema(self, conn, table: str, dialect: str):
        required = {"uuid", "message_id", "content", "created_at"}

        def ok_type(col, typ):
            t = (typ or "").upper()
            if col == "uuid":
                return any(x in t for x in ("CHAR", "TEXT", "UUID"))
            if col == "message_id":
                return any(x in t for x in ("CHAR", "TEXT"))
            if col == "content":
                return any(x in t for x in ("JSON", "TEXT"))
            if col == "created_at":
                return "TIMESTAMP" in t or "DATETIME" in t or "DATE" in t
            return False

        cols = {}
        pk_cols = set()

        if dialect == "sqlite":
            rows = conn.execute(text(f"PRAGMA table_info({table})")).mappings().all()
            for r in rows:
                cols[r["name"]] = r["type"]
                if r["pk"]:
                    pk_cols.add(r["name"])
        elif dialect in ("postgresql", "postgres"):
            colrows = conn.execute(
                text(
                    """
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_name = :t
                    """
                ),
                {"t": table},
            ).all()
            for name, data_type in colrows:
                cols[name] = data_type
            pkrows = conn.execute(
                text(
                    """
                    SELECT kcu.column_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_name = kcu.table_name
                    WHERE tc.table_name = :t AND tc.constraint_type='PRIMARY KEY'
                    """
                ),
                {"t": table},
            ).all()
            pk_cols = {r[0] for r in pkrows}
        else:
            colrows = conn.execute(
                text(
                    """
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_name = :t
                    """
                ),
                {"t": table},
            ).all()
            for name, data_type in colrows:
                cols[name] = data_type
            pk_cols = {"uuid"} if "uuid" in cols else set()

        missing = required - set(cols.keys())
        if missing:
            raise RuntimeError(f"Missing expected columns on '{table}': {sorted(missing)}")

        for c in required:
            if not ok_type(c, cols.get(c, "")):
                raise RuntimeError(f"Column '{c}' has incompatible type '{cols.get(c)}'")

        if "uuid" not in pk_cols:
            raise RuntimeError("Column 'uuid' must be PRIMARY KEY (message_id can repeat)")

    # -------------------- HELPERS --------------------
    def _write_disabled(self):
        return not self.SECURAG_SERVER_WRITE_LOGS

    def _insert_audit(self, message_id: str, content):
        if self._write_disabled():
            return None

        table = self._safe_table_name(self.SECURAG_SERVER_TABLE_NAME)
        dialect = self.engine.dialect.name  # type: ignore[union-attr]

        # Normalize to a list of entries; each entry -> one row
        entries = content if isinstance(content, list) else [content]

        def _to_json_str(obj):
            if isinstance(obj, (dict, list)):
                return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            if isinstance(obj, str):
                return obj
            return json.dumps(obj, default=str)

        results = []

        # simple retry/backoff for sqlite "database is locked"
        delays = [0.05, 0.1, 0.2, 0.4, 0.8]

        try:
            with self.engine.begin() as conn:  # type: ignore[union-attr]
                # Set busy timeout per-connection (extra safety if not set globally)
                if dialect == "sqlite":
                    conn.exec_driver_sql("PRAGMA busy_timeout=5000")

                for entry in entries:
                    new_uuid = str(uuid.uuid4())
                    content_str = _to_json_str(entry)

                    # retry loop
                    for i, delay in enumerate([0.0] + delays):
                        if delay:
                            time.sleep(delay)
                        try:
                            if dialect == "sqlite":
                                conn.execute(
                                    text(f"INSERT INTO {table} (uuid, message_id, content, created_at) "
                                        f"VALUES (:u, :m, :c, CURRENT_TIMESTAMP)"),
                                    {"u": new_uuid, "m": message_id, "c": content_str},
                                )
                            elif dialect in ("postgresql", "postgres"):
                                conn.execute(
                                    text(f"INSERT INTO {table} (uuid, message_id, content, created_at) "
                                        f"VALUES (:u, :m, CAST(:c AS JSONB), NOW())"),
                                    {"u": new_uuid, "m": message_id, "c": content_str},
                                )
                            else:
                                conn.execute(
                                    text(f"INSERT INTO {table} (uuid, message_id, content, created_at) "
                                        f"VALUES (:u, :m, :c, CURRENT_TIMESTAMP)"),
                                    {"u": new_uuid, "m": message_id, "c": content_str},
                                )
                            break
                        except SQLAlchemyError as e:
                            # retry only for sqlite lock contention
                            if dialect == "sqlite" and "database is locked" in str(e).lower() and i < len(delays):
                                continue
                            raise

                    row = conn.execute(
                        text(f"SELECT uuid, message_id, content, created_at FROM {table} WHERE uuid=:u"),
                        {"u": new_uuid},
                    ).first()

                    if not row:
                        raise RuntimeError("Insert succeeded but row not found on re-select")

                    uuid_v, message_id_v, content_v, created_at_v = row
                    try:
                        content_obj = json.loads(content_v) if isinstance(content_v, (str, bytes)) else content_v
                    except Exception:
                        content_obj = {"raw": content_v}

                    created_iso = created_at_v.isoformat() if isinstance(created_at_v, datetime) else str(created_at_v)

                    results.append({
                        "uuid": str(uuid_v),
                        "message_id": message_id_v,
                        "content": content_obj,
                        "created_at": created_iso,
                    })

            # Return list for multiple inserts, single dict otherwise
            return results if isinstance(content, list) else results[0]

        except IntegrityError as e:
            raise e
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to insert audit: {e}") from e

    def _select_audits(self, message_id: str):
        if self._write_disabled():
            return []
        table = self._safe_table_name(self.SECURAG_SERVER_TABLE_NAME)
        try:
            with self.engine.connect() as conn:  # type: ignore[union-attr]
                rows = conn.execute(
                    text(f"SELECT content FROM {table} WHERE message_id=:m"),
                    {"m": message_id},
                ).all()
            items = []
            for (content_v,) in rows:
                if isinstance(content_v, (dict, list)):
                    items.append(content_v)
                else:
                    try:
                        items.append(json.loads(content_v))
                    except Exception:
                        items.append({"raw": content_v})
            items.sort(key=lambda d: (d.get("id") is None, d.get("id")) if isinstance(d, dict) else (True, None))
            return items
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to retrieve audits: {e}") from e

    def _delete_audits(self, message_id: str):
        if self._write_disabled():
            return 0
        table = self._safe_table_name(self.SECURAG_SERVER_TABLE_NAME)
        try:
            with self.engine.begin() as conn:  # type: ignore[union-attr]
                res = conn.execute(text(f"DELETE FROM {table} WHERE message_id=:m"), {"m": message_id})
            return int(getattr(res, "rowcount", 0) or 0)
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to delete audits: {e}") from e

    # -------------------- ROUTES --------------------
    def _setup_routes(self):
        @self.app.route('/api/transform-input', methods=['POST'])
        def transform_input():
            try:
                data = request.get_json(silent=True) or {}
                content = data.get("content")
                message_id = data.get("message_id")
                write_log = data.get("write_log", False)

                if content is None:
                    return make_response(jsonify({"error": "content is required"}), 400)

                if message_id is None and self.SECURAG_SERVER_WRITE_LOGS and write_log:
                    return make_response(jsonify({"error": "message_id is required when SECURAG_SERVER_WRITE_LOGS is true"}), 400)

                transformed_content = self.executor.execute_inputs(content)
                audit_logs = self.executor.get_logs()

                if write_log and self.SECURAG_SERVER_WRITE_LOGS and message_id:
                    self._insert_audit(message_id=message_id, content=audit_logs)

                flagged_response = None
                flagged = any(i.get_flag() for i in self.executor.input_pipes)

                response = jsonify({"detail": "Success", "flagged": flagged, "transformed_content": transformed_content, "audit_logs": audit_logs})
                return make_response(response, 200)
            except FlaggedInputError:
                audit_logs = self.executor.get_logs()
                if write_log and self.SECURAG_SERVER_WRITE_LOGS and message_id:
                    self._insert_audit(message_id=message_id, content=audit_logs)
                flagged_response = "\n".join([i.flagged_response() for i in self.executor.input_pipes])
                flagged = True
                response = jsonify({"detail": "Flagged", "flagged": flagged, "transformed_content": flagged_response, "audit_logs": audit_logs})
                return make_response(response, 200)
            except Exception as e:
                logger.error("An error occurred: %s", str(e), exc_info=True)
                response = jsonify({"detail": "An error occurred"})
                return make_response(response, 500)

        @self.app.route('/api/transform-output', methods=['POST'])
        def transform_output():
            try:
                data = request.get_json(silent=True) or {}
                content = data.get("content")
                message_id = data.get("message_id")
                write_log = data.get("write_log", False)

                if content is None:
                    return make_response(jsonify({"error": "content is required"}), 400)

                if message_id is None and self.SECURAG_SERVER_WRITE_LOGS and write_log:
                    return make_response(jsonify({"error": "message_id is required when SECURAG_SERVER_WRITE_LOGS is true"}), 400)

                transformed_content = self.executor.execute_outputs(content)
                audit_logs = self.executor.get_logs()

                if write_log and self.SECURAG_SERVER_WRITE_LOGS and message_id:
                    self._insert_audit(message_id=message_id, content=audit_logs)

                flagged = any(i.get_flag() for i in self.executor.output_pipes)
                flagged_response = "\n".join([i.flagged_response() for i in self.executor.output_pipes])

                response = jsonify({"detail": "Success", "flagged": flagged, "transformed_content": transformed_content, "audit_logs": audit_logs})
                return make_response(response, 200)
            except FlaggedOutputError:
                audit_logs = self.executor.get_logs()
                if write_log and self.SECURAG_SERVER_WRITE_LOGS and message_id:
                    self._insert_audit(message_id=message_id, content=audit_logs)

                flagged_response = "\n".join([i.flagged_response() for i in self.executor.output_pipes])
                flagged = True
                response = jsonify({"detail": "Flagged", "flagged": flagged, "transformed_content": flagged_response, "audit_logs": audit_logs})
                return make_response(response, 200)
            except Exception as e:
                logger.error("An error occurred: %s", str(e), exc_info=True)
                response = jsonify({"detail": "An error occurred"})
                return make_response(response, 500)
            
        @self.app.route('/api/ai-response', methods=['POST'])
        def ai_response():
            try:
                data = request.get_json(silent=True) or {}
                ai_response = self.ai_response.run(**data)
                response = jsonify({"detail": "Success", "ai_response": ai_response})
                return make_response(response, 200)
            except Exception as e:
                print(f"Error occurred in /api/ai-response: {str(e)}", traceback.format_exc())
                logger.error("An error occurred: %s", str(e), exc_info=True)
                response = jsonify({"detail": "An error occurred"})
                return make_response(response, 500)


        # @self.app.route("/api/audit/create/", methods=["POST"])
        # def create_audit():
        #     if self._write_disabled():
        #         return make_response(jsonify({"message": "Auditing disabled on SecuRAG-Server. All Audting related operations are forbidden."}), 403)

        #     data = request.get_json(silent=True) or {}
        #     message_id = str(data.get("message_id", "")).strip()
        #     content = data.get("content", None)

        #     if not message_id:
        #         return make_response(jsonify({"error": "message_id is required"}), 400)
            
        #     if content is None:
        #         return make_response(jsonify({"error": "content is required"}), 400)
        
            
        #     if not isinstance(content, (dict, list)):
        #         return make_response(jsonify({"error": "content must be a dict, list or a valid JSON string"}), 400)
        #     if isinstance(content, str):
        #         try:
        #             content = json.loads(content)
        #         except json.JSONDecodeError:
        #             return make_response(jsonify({"error": "If content is a string, it must be valid JSON"}), 400)

        #     try:
        #         result = self._insert_audit(message_id, content)
        #         return make_response(jsonify(result), 201)
        #     except IntegrityError as e:
        #         return make_response(jsonify({"error": str(e)}), 409)
        #     except Exception as e:
        #         logger.exception("create_audit failed")
        #         return make_response(jsonify({"error": str(e)}), 500)

        @self.app.route("/api/audit/<string:message_id>/", methods=["GET"])
        def retrieve_audits(message_id: str | None = None):
            if self._write_disabled():
                return make_response(jsonify({"message": "Auditing disabled on SecuRAG-Server. All Audting related operations are forbidden."}), 403)

            try:
                items = self._select_audits(str(message_id))
                return make_response(jsonify(items), 200)
            except Exception as e:
                logger.exception("retrieve_audits failed")
                return make_response(jsonify({"error": str(e)}), 500)

        @self.app.route("/api/audit/<string:message_id>/delete/", methods=["DELETE"])
        def delete_audits(message_id: str | None = None):
            if self._write_disabled():
                return make_response(jsonify({"message": "Auditing disabled on SecuRAG-Server. All Audting related operations are forbidden."}), 403)

            try:
                deleted = self._delete_audits(str(message_id))
                return make_response(jsonify({"deleted": deleted}), 200)
            except Exception as e:
                logger.exception("delete_audits failed")
                return make_response(jsonify({"error": str(e)}), 500)

    # -------------------- RUN --------------------
    def run(self, host='0.0.0.0', port=5000, debug=False):
        self.app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    app = SecuRAGServer("SecuRAG-Flask", executor=executor, ai_response=ai_response)
    app.run(debug=False)
