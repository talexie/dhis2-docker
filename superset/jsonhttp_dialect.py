from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.engine import create_engine
from sqlalchemy.sql.compiler import SQLCompiler
from sqlalchemy import types
import requests
import pandas as pd
import duckdb

class JSONHTTPDialect(DefaultDialect):
    name = "dhis2"
    supports_statement_cache = False

    def create_connect_args(self, url):
        """
        Parse the connection URL to extract credentials and JSON endpoint.
        """
        host = url.host
        username = url.username
        password = url.password
        endpoint = f"https://{host}" if not host.startswith("http") else host

        return (endpoint,), {
            "auth": (username, password),
            "duckdb_path": url.query.get("duckdb_path", ":memory:"),
        }

    def execute_json_query(self, url, auth, duckdb_path, table_name):
        """
        Fetch JSON data and save it into DuckDB.
        """
        # Fetch JSON data
        response = requests.get(url, auth=auth)
        response.raise_for_status()
        data = response.json()

        # Convert to Pandas DataFrame
        df = pd.DataFrame(data)

        # Save to DuckDB
        conn = duckdb.connect(duckdb_path)
        conn.register("temp_table", df)
        conn.execute(f"CREATE TABLE {table_name} AS SELECT * FROM temp_table")
        conn.unregister("temp_table")

        return conn

    def execute(self, cursor, statement, parameters, context=None):
        """
        Override execute to handle fetching JSON and saving to DuckDB.
        """
        conn = context["dialect"].execute_json_query(
            url=parameters["url"],
            auth=parameters["auth"],
            duckdb_path=parameters["duckdb_path"],
            table_name=parameters["table_name"],
        )
        return conn.execute(statement)

# Register the custom dialect
from sqlalchemy.dialects import registry
registry.register("dhis2", __name__, "JSONHTTPDialect")
