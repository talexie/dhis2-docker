# Apache Superset Docker file for ALKIP Platform
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
ARG superset_version="4.0.2"
FROM apache/superset:${superset_version}

USER root
COPY --chown=superset:superset --chmod=644 superset/dhis2.py /app/superset/db_engine_specs/dhis2.py
COPY --chown=superset:superset --chmod=644 superset/jsonhttp_dialect.py /app/jsonhttp_dialect.py
WORKDIR /app
RUN pip install -e /app/jsonhttp_dialect.py
USER superset

CMD ["/usr/bin/run-server.sh"]
