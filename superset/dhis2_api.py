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

from __future__ import annotations

import re
from datetime import datetime
from re import Pattern
from typing import Any, TYPE_CHECKING, TypedDict

from marshmallow import fields, Schema
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_babel import gettext as __
from sqlalchemy import types
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.engine.url import URL

from superset.sql_parse import ParsedQuery
from superset.models.sql_lab import Query
from superset.config import VERSION_STRING
from superset.constants import TimeGrain, USER_AGENT
from superset.databases.utils import make_url_safe
from superset.db_engine_specs.base import BaseEngineSpec, BasicParametersType, BasicParametersMixin, LimitMethod
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from superset.utils.filters import get_dataset_access_filters
from superset.views.base import BaseFilter
from superset.models.helpers import ExploreMixin

import duckdb, requests, sqlglot
from requests import Session
from requests.auth import HTTPBasicAuth
from sqlglot.expressions import Expression, Identifier, Literal, In, And, EQ, Column
from sqlalchemy_dhis2.connection import add_authorization
from sqlalchemy_dhis2.exceptions import DatabaseHTTPError
from sqlalchemy_dhis2.constants import _HEADER
import polars as pd

if TYPE_CHECKING:
    # prevent circular imports
    from superset.models.core import Database

COLUMN_DOES_NOT_EXIST_REGEX = re.compile("no such column: (?P<column_name>.+)")
DEFAULT_ACCESS_TOKEN_URL = (
    "https://app.motherduck.com/token-request?appName=Superset&close=y"
)


# schema for adding a database by providing parameters instead of the
# full SQLAlchemy URI
class Dhis2ApiParametersSchema(Schema):
    access_token = fields.String(
        allow_none=False,
        metadata={"description": __("DHIS2 PAT token")},
        load_default=DEFAULT_ACCESS_TOKEN_URL,
    )
    username = fields.String(
        allow_none=True,
        metadata={"description": __("DHIS2 psername")},
        load_default="",
    )

    database = fields.String(
        required=False, metadata={"description": __("DHIS2 virtual database")}
    )
    query = fields.Dict(
        keys=fields.Str(),
        values=fields.Raw(),
        metadata={"description": __("Additional parameters")},
    )


class Dhis2ApiParametersType(BasicParametersType):
    access_token: str | None
    username: str | None
    database: str
    query: dict[str, Any]


class Dhis2ApiPropertiesType(TypedDict):
    parameters: Dhis2ApiParametersType


class Dhis2ApiParametersMixin(BasicParametersMixin):
    """
    Mixin for configuring DB engine specs via a dictionary.

    With this mixin the SQLAlchemy engine can be configured through
    individual parameters, instead of the full SQLAlchemy URI. This
    mixin is for DuckDB:

        dhis2://username:password@your-json-endpoint.com?duckdb_path=/path/to/your_duckdb.db

    """

    engine = "dhis2"

    # schema describing the parameters used to configure the DB
    parameters_schema = Dhis2ApiParametersSchema()

    # recommended driver name for the DB engine spec
    default_driver = "dhis2"

    # query parameter to enable encryption in the database connection
    # for Postgres this would be `{"sslmode": "verify-ca"}`, eg.
    encryption_parameters: dict[str, str] = {}

    @staticmethod
    def _is_motherduck(database: str) -> bool:
        return "md:" in database
    
    @classmethod
    def build_sqlalchemy_uri(  # pylint: disable=unused-argument
        cls,
        parameters: Dhis2ApiParametersType,
        encrypted_extra: dict[str, str] | None = None,
    ) -> str:
        """
        Build SQLAlchemy URI for connecting to a DuckDB database.
        If an access token is specified, return a URI to connect to a MotherDuck database.
        """
        if parameters is None:
            parameters = {}
        query = parameters.get("query", {}).copy()
        database = parameters.get("database", ":memory:")
        if parameters.get("encryption"):
            if not cls.encryption_parameters:
                raise Exception(  # pylint: disable=broad-exception-raised
                    "Unable to build a URL with encryption enabled"
                )
            query.update(cls.encryption_parameters)

        return str(URL(drivername=cls.engine, database=database, query=query,username=parameters.get("username"),
                password=parameters.get("password")))

    @classmethod
    def get_parameters_from_uri(  # pylint: disable=unused-argument
        cls, uri: str, encrypted_extra: dict[str, Any] | None = None
    ) -> Dhis2ApiParametersType:
        url = make_url_safe(uri)
        query = {
            key: value
            for (key, value) in url.query.items()
            if (key, value) not in cls.encryption_parameters.items()
        }
        encryption = all(
            item in url.query.items() for item in cls.encryption_parameters.items()
        )
        access_token = query.pop("access_token", "")
        return {
            "username": url.username,
            "password": url.password,
            "host": url.host,
            "port": url.port,
            "access_token": access_token,
            "database": url.database,
            "query": query,
            "encryption": encryption,
        }

    @classmethod
    def validate_parameters(
        cls, properties: Dhis2ApiPropertiesType
    ) -> list[SupersetError]:
        """
        Validates any number of parameters, for progressive validation.
        """
        errors: list[SupersetError] = []

        parameters = properties.get("parameters", {})
        if cls._is_motherduck(parameters.get("database", "")):
            required = {"access_token"}
        else:
            required = set()
        present = {key for key in parameters if parameters.get(key, ())}

        if missing := sorted(required - present):
            errors.append(
                SupersetError(
                    message=f'One or more parameters are missing: {", ".join(missing)}',
                    error_type=SupersetErrorType.CONNECTION_MISSING_PARAMETERS_ERROR,
                    level=ErrorLevel.WARNING,
                    extra={"missing": missing},
                ),
            )

        return errors

    @classmethod
    def parameters_json_schema(cls) -> Any:
        """
        Return configuration parameters as OpenAPI.
        """
        if not cls.parameters_schema:
            return None

        spec = APISpec(
            title="Database Parameters",
            version="1.0.0",
            openapi_version="3.0.2",
            plugins=[MarshmallowPlugin()],
        )
        spec.components.schema(cls.__name__, schema=cls.parameters_schema)
        return spec.to_dict()["components"]["schemas"][cls.__name__]

class Dhis2ApiEngineSpec(Dhis2ApiParametersMixin,BaseEngineSpec, BaseFilter, ExploreMixin):
    engine = "dhis2"
    engine_name = "DHIS2 API Analytics"
    #session = Session()
    q_filters = []
    
    sqlalchemy_uri_placeholder = (
        "dhis2://username:password@your-json-endpoint.com?duckdb_path=/path/to/your_duckdb.db"
    )
    _time_grain_expressions = {
        None: "{col}",
        TimeGrain.SECOND: "DATE_TRUNC('second', {col})",
        TimeGrain.MINUTE: "DATE_TRUNC('minute', {col})",
        TimeGrain.HOUR: "DATE_TRUNC('hour', {col})",
        TimeGrain.DAY: "DATE_TRUNC('day', {col})",
        TimeGrain.WEEK: "DATE_TRUNC('week', {col})",
        TimeGrain.MONTH: "DATE_TRUNC('month', {col})",
        TimeGrain.QUARTER: "DATE_TRUNC('quarter', {col})",
        TimeGrain.YEAR: "DATE_TRUNC('year', {col})",
    }

    custom_errors: dict[Pattern[str], tuple[str, SupersetErrorType, dict[str, Any]]] = {
        COLUMN_DOES_NOT_EXIST_REGEX: (
            __('We can\'t seem to resolve the column "%(column_name)s"'),
            SupersetErrorType.COLUMN_DOES_NOT_EXIST_ERROR,
            {},
        ),
    }
    
    @classmethod
    def epoch_to_dttm(cls) -> str:
        return "datetime({col}, 'unixepoch')"

    @classmethod
    def convert_dttm(
        cls, target_type: str, dttm: datetime, db_extra: dict[str, Any] | None = None
    ) -> str | None:
        sqla_type = cls.get_sqla_column_type(target_type)

        if isinstance(sqla_type, (types.String, types.DateTime)):
            return f"""'{dttm.isoformat(sep=" ", timespec="microseconds")}'"""
        return None
    @classmethod
    def get_analytics_uri(cls,url):
        port = url.get('port')
        
        if  port is None or port == 443:
            return f"{url.get('host')}"
        else:
            return f"{url.get('host')}:{ port }"
        
    @classmethod
    def execute(  # pylint: disable=unused-argument
        cls,
        cursor: Any,
        query: str,
        database: Database,
        **kwargs: Any,
    ) -> None:
        session = Session()
        url = cls.get_parameters_from_uri(database.sqlalchemy_uri_decrypted)
        analytics_url = cls.get_analytics_uri(url)
        token = HTTPBasicAuth(url.get('username'),url.get('password'))
        conn = duckdb.connect(database=":memory:")
        add_authorization(session=session, username=url.get('username'), password=url.get('password'),token=None)
        parsed = sqlglot.parse(sql=query,read="duckdb")
        filters, tables = cls.extract_tables_and_filters(parsed[0])
        analytics_dim = cls.create_analytics_dimension(filters) 
        cls.q_filters.append({
            't':tables,
            'd': filters
        }) 
        print("1:",query)
        print("2:",analytics_dim)
        print("3:",tables)
        print('4:',cls.q_filters)
        import pprint
        
        print("Model:",cls.model)
        #print("FIL:",get_dataset_access_filters(database))
        print(database.data)
        print('6:',cls.get_query_str_extended(query))
        print('7:',cls.get_sqla_query())
        if analytics_dim is not None and 'analytics' in tables:
            url_endpoint = f"https://{ analytics_url }/{ url.get('database','')}/api/analytics/rawData.json?dimension={analytics_dim}&dimension=ou:USER_ORGUNIT&dimension=pe:LAST_12_MONTHS&outputIdScheme=NAME&outputOrgUnitIdScheme=NAME"
            print(url_endpoint)
            response = session.get(url=url_endpoint,headers=_HEADER,)
            #if response.status_code != 2:
            #    raise DatabaseHTTPError(response.text, response.status_code)
            #    # Convert to Pandas DataFrame
            data = response.json()
            
            df = pd.DataFrame(cls.format_analytics_data(data))
            if df.is_empty():
                cls.execute(cursor,'select * from analytics',database, **kwargs)
            else:
                conn.register(f"analytics_temp", df)
                conn.execute(f"DROP TABLE IF EXISTS analytics")
                conn.execute(f"CREATE TABLE analytics AS SELECT * FROM analytics_temp")
                conn.unregister(f"analytics_temp") 
                cls.execute(cursor,'select * from analytics',database, **kwargs)   
        else:
            super().execute(cursor,query,database, **kwargs) 
    
    @classmethod
    def format_analytics_data(cls,data=dict()):
        headers = data.get('headers',[])
        keys = [header["name"] for header in headers]
        rows = data.get("rows",[])
        formatted_data = [dict(zip(keys, row)) for row in rows]
        return formatted_data
        
    @classmethod   
    def create_analytics_dimension(cls,filters):
        dimension = []
        for f in filters:
            for filter in f:
                if filter['op'] == 'in' and filter['key'] in ['id']:
                    dimension.extend(filter['value'] )
                else:
                    pass
        if not dimension:
            return None
        else:
            return f"dx:{ ';'.join(map(str, dimension)) }"
    
    @classmethod
    def fetch_data(cls, cursor: Any, limit: int | None = None) -> list[tuple[Any, ...]]:
        """

        :param cursor: Cursor instance
        :param limit: Maximum number of rows to be returned by the cursor
        :return: Result of query
        """
        if cls.arraysize:
            cursor.arraysize = cls.arraysize
        try:
            if cls.limit_method == LimitMethod.FETCH_MANY and limit:
                return cursor.fetchmany(limit)
            data = cursor.fetchall()
            print("cusr:",data)
            description = cursor.description or []
            # Create a mapping between column name and a mutator function to normalize
            # values with. The first two items in the description row are
            # the column name and type.
            column_mutators = {
                row[0]: func
                for row in description
                if (
                    func := cls.column_type_mutators.get(
                        type(cls.get_sqla_column_type(cls.get_datatype(row[1])))
                    )
                )
            }
            if column_mutators:
                indexes = {row[0]: idx for idx, row in enumerate(description)}
                for row_idx, row in enumerate(data):
                    new_row = list(row)
                    for col, func in column_mutators.items():
                        col_idx = indexes[col]
                        new_row[col_idx] = func(row[col_idx])
                    data[row_idx] = tuple(new_row)

            return data
        except Exception as ex:
            raise cls.get_dbapi_mapped_exception(ex) from ex
        
    @staticmethod
    def get_table_from_json(url: str, table_name: str) -> str:
        """
        Reads JSON data from an HTTP endpoint and loads it into a DuckDB table.
        
        :param url: The JSON API endpoint.
        :param table_name: Name of the table to be created in DuckDB.
        :return: Name of the created table.
        """
        print(f"DHIS2 API HTTP connection from { url } for table { table_name }")
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
    def get_table_names(
        cls, database: Database, inspector: Inspector, schema: str | None
    ) -> set[str]:
        return set(inspector.get_table_names(schema))
    
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
    
    @classmethod
    def update_impersonation_config(  # pylint: disable=too-many-arguments
        cls,
        database: Database,
        connect_args: dict[str, Any],
        uri: str,
        username: str | None,
        access_token: str | None,
    ) -> None:
        """
        Update a configuration dictionary
        that can set the correct properties for impersonating users
        :param database: the Database object
        :param connect_args: config to be updated
        :param uri: URI string
        :param username: Effective username
        :param access_token: Personal access token for OAuth2
        :return: None
        """
        url = make_url_safe(uri)
        backend_name = url.get_backend_name()

        # Must be DHIS2 API connection, enable impersonation, and set optional param
        # auth=LDAP|KERBEROS
        # Set principal_username=$effective_username
        if backend_name == "dhis2" and username is not None:
            connect_args["user"] = username
            if access_token is not None:
                http_session = requests.Session()
                http_session.headers.update({"Authorization": f"Bearer {access_token}"})
                connect_args["http_session"] = http_session
            if username is not None and url.password is not None:
                http_session = requests.Session()
                http_session.auth(username,url.password)
                connect_args["http_session"] = http_session
    


    @staticmethod
    def get_extra_params(database: Database) -> dict[str, Any]:
        """
        Add a user agent to be used in the requests.
        """
        extra: dict[str, Any] = BaseEngineSpec.get_extra_params(database)
        engine_params: dict[str, Any] = extra.setdefault("engine_params", {})
        connect_args: dict[str, Any] = engine_params.setdefault("connect_args", {})
        config: dict[str, Any] = connect_args.setdefault("config", {})
        custom_user_agent = config.pop("custom_user_agent", "")
        delim = " " if custom_user_agent else ""
        user_agent = USER_AGENT.replace(" ", "-").lower()
        user_agent = f"{user_agent}/{VERSION_STRING}{delim}{custom_user_agent}"
        config.setdefault("custom_user_agent", user_agent)

        return extra
    
    @staticmethod
    def get_filters_display(context: dict) -> dict:
        """
        Extracts applied filters from the query context and formats them by name.
        """
        # Extract filters from the query context
        filters = context.get("extra", {}).get("filters", [])
        
        # Map filter names to their values
        filter_display = {
            filter_item["col"]: filter_item["val"] 
            for filter_item in filters
        }
        print(f"context spec:{ context}")
        return filter_display
    
    def get_parameters(self,context: dict) -> dict:
        """
        Include the filters in the parameters for custom processing.
        """
        print(f"Called:{context}")
        # Get standard parameters
        parameters = super().get_parameters(context)
        print(f"Super Params: { parameters }")
        # Add filters display
        parameters["applied_filters"] = self.get_filters_display(context)
        return parameters
    
    def set_or_update_query_limit(self, sql: str, limit: int,**kwargs) -> str:
        """
        Create a query based on original query but with new limit clause

        :param sql: SQL query
        :param limit: New limit to insert/replace into query
        :return: Query with new limit
        """
        parsed_q = self.apply_limit_offset(sql, limit, **kwargs)
        print(f"X1:{parsed_q}")
        print(f"X2:{kwargs}")
        parsed_query = ParsedQuery(sql, engine=self.engine)
        print(f"Limit Query:{parsed_query}")
        return parsed_query.set_or_update_query_limit(limit)
    
    def apply_limit_offset(self,sql, limit, **kwargs):
        filters = kwargs.get('query_context', {}).get('filters', [])
        return f"{sql} WHERE {self.process_filters(filters)} LIMIT {limit}"

    def process_filters(filters):
        # Convert frontend filters into SQL WHERE clauses
        return " AND ".join(f"{filter['col']} = '{filter['val']}'" for filter in filters)
    
    @classmethod
    def extract_filter_values(cls,condition):
        filters = []

        def get_key_value(expression):
            key = None
            value = ""
            for exp in expression.iter_expressions():
                if isinstance(exp, Column):
                    key = exp.sql()
                elif isinstance(exp, Literal):
                    value = exp.this
                else:
                    pass
            return key, value
            
        def extract_values(expression):
            f = {}
            if isinstance(expression, EQ):
                key, value = get_key_value(expression)
                f = { 'key':key, 'value': value,'op': 'eq'}
            elif isinstance(expression, In):
                values = [arg.this for arg in expression.expressions]
                filters.append({ 'key': expression.this.sql(), 'value': values,'op': 'in'})
            elif isinstance(expression, dict):
                for key, value in expression.items():
                    extract_values(value)
            """
            elif isinstance(expression, Expression):
                for child in expression.args.values():
                    print(f"{child}::")
                    if isinstance(child, list):
                        for item in child:
                            extract_values(item)
                    elif child:
                        extract_values(child)
            """
            return f
        
        def traverse_ast(node):
            if isinstance(node, Expression):
                value = extract_values(node)
                if value:
                    filters.append(value)
                for child in node.args.values():
                    if isinstance(child, list):
                        for item in child:
                            traverse_ast(item)
                    elif child:
                        traverse_ast(child)

        traverse_ast(condition)
        return filters

    @classmethod
    def extract_tables_and_filters(cls,node):
        filters = []
        tables = set()
        
        for subnode in node.walk():
            if isinstance(subnode, sqlglot.expressions.Table):
                tables.add(subnode.name)
            elif isinstance(subnode, sqlglot.expressions.Where):
                for condition in subnode.iter_expressions():
                    filters.append(cls.extract_filter_values(condition))

        return filters, tables