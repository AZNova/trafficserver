/** @file

    Include file for  ...

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

#include <string>
#include <deque>
#include <ts/ts.h>

#ifndef STATS_H_
#define STATS_H_

struct Statistics {
  int certs_loaded_current;
  int certs_loaded_total;
  int certs_blacklisted;
  int certs_evicted_total;
  int domain_lookup_failed;
  int cert_lookup_failed;
  int requests;
  int timeouts;
  int size; // average
};

TSReturnCode StatsInit();

extern Statistics statistics;

// class SSLStats
//{
// public:
//  TSMutex mutex;
//  static std::string counter_name;
//  int id;
//
//  SSLStats();
//  SSLStats(std::string name);
//  ~SSLStats();
//  void increment();
////  int get();
//};

#endif
