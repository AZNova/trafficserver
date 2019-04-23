/** @file

    SSL dynamic certificate loader
    Loads certificates into a hash table as they are requested

    @section license License

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include <stdio.h>
#include <memory.h>
#include <inttypes.h>
#include <algorithm>
#include <ts/ts.h>

#include "stats.h"

#define PN "ssl-lazy-loader-stats"

Statistics statistics;
// std::string SSLStats::counter_name = "proxy.node.ssl_certs_loaded";

TSReturnCode
StatsInit()
{
  statistics.certs_loaded_current =
    TSStatCreate(PN ".certs_loaded_current", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.certs_loaded_total =
    TSStatCreate(PN ".certs_loaded_total", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.certs_evicted_total =
    TSStatCreate(PN ".certs_evicted_total", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.certs_blacklisted =
    TSStatCreate(PN ".certs_blacklisted", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.domain_lookup_failed =
    TSStatCreate(PN ".domain_lookup_failed", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.cert_lookup_failed =
    TSStatCreate(PN ".cert_lookup_failed", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.requests = TSStatCreate(PN ".requests", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.timeouts = TSStatCreate(PN ".timeouts", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  statistics.size = TSStatCreate(PN ".size", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_AVG);

  return TS_SUCCESS;
}

// SSLStats::SSLStats(): counter_name(""), id(0){
//  mutex = TSMutexCreate();
//}
//
// SSLStats::SSLStats(std::string name){
//  mutex = TSMutexCreate();
//  counter_name = name;
//  id = TSStatCreate(counter_name.c_str(), TS_RECORDDATATYPE_INT,
//                    TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
//}
//
// SSLStats::~SSLStats() {
//}
//
// void
// SSLStats::increment() {
//  TSMutexLock(mutex);
//  TSStatIntIncrement(id, 1);
//  TSMutexUnlock(mutex);
//}
