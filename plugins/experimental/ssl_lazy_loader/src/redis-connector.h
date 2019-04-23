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

#ifndef REDIS_CONNECTOR_H
#define REDIS_CONNECTOR_H
#include <string>
#include <cstring>
#include <vector>
#include <deque>
#include <hiredis/hiredis.h>
#include "ts/ts.h"
#include <tsconfig/TsValue.h>
// #include "ts/ink_config.h"
// #include "ts/ink_inet.h"
// #include "ts/ink_time.h"
#include "tscore/ink_hrtime.h"
#include "ipaddr.h"
#include "sslentry.h"

using ts::config::Configuration;
using ts::config::Value;

extern std::string RedisConfigPath;
extern Configuration RedisConfig; // global configuration
extern int RedisBlacklistLRU;
extern int RedisBlacklistTime;
extern int RedisEvictFrequency;
extern int RedisCertTTL;
;

class RedisNode
{
public:
  std::string redis_table;
  IpAddr redis_ipAddr;
  int redis_port;
  std::string redis_pass;
  redisContext *r_ctx;
  //  redisReply *r_reply;

  // RedisNode() : redis_port(0), redis_pass(""), r_ctx(NULL),
  //  r_reply(NULL) {}
  RedisNode() : redis_port(0), redis_pass(""), r_ctx(NULL) {}

  ~RedisNode()
  {
    char val1[256];
    TSDebug("redis-connector", "Destroying a RedisNode for %s ", redis_ipAddr.toString(val1, sizeof(val1)));
    if (r_ctx)
      redisFree(r_ctx);
    //    if (r_reply)
    //      freeReplyObject(r_reply);
  }

  redisContext *r_connect();
  void *r_send(redisReply *&r_reply, const char *format, ...);
  int get_resp_simple_str(redisReply *reply);
  int exists(redisReply *&r_reply, std::string servicename, const char *key);
  int sismember(redisReply *&r_reply, std::string servicename, const char *servername);
};

void Parse_Redis_Config(Value &parent, RedisNode &orig_values);
void Parse_Redis_Rules(Value &parent, RedisNode &orig_values);
void Parse_Redis_Local_Config(Value &parent, RedisNode &orig_values);
void Parse_Redis_Local_Rules(Value &parent, RedisNode &orig_values);
int Load_Redis_Config_File(void);
int Load_Redis_Configuration(void);

class RequestDeque
{
public:
  std::deque<SslEntry *> requestDeque;
  TSMutex mutex;

  RequestDeque() { mutex = TSMutexCreate(); }
};

extern RequestDeque Requests;

class NodeDeque
{
public:
  std::deque<RedisNode *> nodeDeque;

  RedisNode *exists(std::string);
  RedisNode *ip_exists(IpAddr ip);
  void Dump_Node_Config(void);
};

extern NodeDeque ndSentinels;
extern NodeDeque ndSpecifics;

// class SentinelDeque
//{
// public:
//  std::deque<RedisNode*> sentinelDeque;
//
//  void Dump_Node_Config(void);
//};
//
// extern SentinelDeque Sentinels;

class RedisConnector
{
public:
  std::string cluster_name;
  NodeDeque ndsentinels;
  // SentinelDeque sentinels;

  TSMutex mutex;
  RedisNode *sentinel;
  redisContext *sentinel_r_ctx;

  RedisNode *master_node;

  // RedisConnector() : cluster_name(""), sentinels(Sentinels),
  //  mutex(NULL), sentinel_r_ctx(NULL) {}
  RedisConnector(std::string &name, NodeDeque &sentinels_dq);
  // RedisConnector(std::string &name, SentinelDeque &sentinels_dq);
  ~RedisConnector();

  bool change_master(void);
  RedisNode *get_sentinel(void);
  RedisNode *get_master(RedisNode *);
  RedisNode *get_master_from_sentinel(RedisNode *new_master_node);
  // RedisNode *get_sentinel(SentinelDeque &sentinels);
  RedisNode *get_master(void);

  int auth(redisReply *&r_reply, std::string servicename);
  int get(redisReply *&r_reply, std::string servicename, const char *key);
};

// class RedisReply
//{
// public:
//  redisReply r_reply;
//
////  parse_info();
////  parse_sentinel_state();
////  parse_sentinel_master();
////  parse_sentinel_masters();
////  parse_sentinel_slaves_and_sentinels();
////  parse_sentinel_get_master();
//
//};
#endif
