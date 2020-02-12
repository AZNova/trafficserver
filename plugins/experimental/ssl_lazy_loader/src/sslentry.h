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
#ifndef SSLENTRY_H
#define SSLENTRY_H
#include <stdio.h>
#include <memory.h>
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <string>
#include <typeinfo>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
// #include "ts/ink_time.h"
#include "tscore/ink_hrtime.h"

typedef enum {
  SSL_HOOK_OP_DEFAULT,                     ///< Null / initialization value. Do normal processing.
  SSL_HOOK_OP_TUNNEL,                      ///< Switch to blind tunnel
  SSL_HOOK_OP_TERMINATE,                   ///< Termination connection / transaction.
  SSL_HOOK_OP_LAST = SSL_HOOK_OP_TERMINATE ///< End marker value.
} SslVConnOp;

class SslEntry
{
public:
  SslEntry() : ctx(NULL), op(SSL_HOOK_OP_DEFAULT), mutex(TSMutexCreate()) {}

  ~SslEntry() {}

  SSL_CTX *ctx;
  SslVConnOp op;
  // If the CTX is not already created, use these
  // files to load things up
  std::string certFileName;
  std::string keyFileName;
  std::string request_domain;
  TSMutex mutex = TSMutexCreate();
  std::deque<TSVConn> waitingVConns;
  time_t load_time   = 0;
  time_t access_time = 0;
  // Common Name fetched from redis
  std::string redis_CN;

  void
  set_load_time(time_t this_time)
  {
    load_time = this_time;
  }

  void
  set_access_time(time_t this_time)
  {
    access_time = this_time;
  }
};

#endif
