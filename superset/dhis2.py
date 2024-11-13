# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from superset.db_engine_specs.base import BaseEngineSpec
from sqlalchemy.engine.url import URL
import duckdb, requests

class Dhis2EngineSpec(BaseEngineSpec):
    engine = "duckdb"
    engine_name = "DHIS2 Analytics"
    
    @staticmethod
    def get_table_from_json(url: str, table_name: str) -> str:
        """
        Reads JSON data from an HTTP endpoint and loads it into a DuckDB table.
        
        :param url: The JSON API endpoint.
        :param table_name: Name of the table to be created in DuckDB.
        :return: Name of the created table.
        """
        # Establish a connection to DuckDB
        conn = duckdb.connect(database=":memory:")  # or use a file-based database

        # Use DuckDB's SQL to read JSON directly from the URL
        try:
            conn.execute(f"""
                CREATE TABLE {table_name} AS
                SELECT * FROM read_json_auto('{url}')
            """)
            return table_name
        except Exception as e:
            raise Exception(f"Failed to load JSON data from {url} into DuckDB: {e}")
    
    @classmethod
    def get_sqla_table(cls, table_name: str, json_url: str) -> URL:
        """
        Generates a SQLAlchemy-compatible URL for a DuckDB table created from JSON data.
        
        :param table_name: The table name in DuckDB.
        :param json_url: The JSON URL to be loaded as a DuckDB table.
        :return: SQLAlchemy URL.
        """
        # Load the JSON data into a DuckDB table
        cls.get_table_from_json(json_url, table_name)
        
        # Return a SQLAlchemy URL to DuckDB (in-memory or file)
        return URL.create("duckdb", database=":memory:")