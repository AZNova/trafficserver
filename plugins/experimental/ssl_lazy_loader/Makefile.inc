#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/ssl_lazy_loader/ssl_lazy_loader.la

experimental_ssl_lazy_loader_ssl_lazy_loader_la_SOURCES = \
  experimental/ssl_lazy_loader/src/ssl-lazy-loader.cc \
  experimental/ssl_lazy_loader/src/domain-tree.cc \
  experimental/ssl_lazy_loader/src/redis-connector.cc \
  experimental/ssl_lazy_loader/src/ssl-utils.cc \
  experimental/ssl_lazy_loader/src/stats.cc

experimental_ssl_lazy_loader_ssl_lazy_loader_la_LIBADD = \
    $(TS_PLUGIN_LDFLAGS) \
    $(top_builddir)/lib/tsconfig/libtsconfig.la \
    $(LIB_HIREDIS)
