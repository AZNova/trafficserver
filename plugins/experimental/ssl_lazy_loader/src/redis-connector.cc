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
#include <sys/time.h>
#include <iostream>
#include <random>
#include "ts/ts.h"
// #include "ts/ink_config.h"
#include <tsconfig/TsValue.h>
#include "redis-connector.h"
#include "ssl-utils.h"

using ts::config::Configuration;
using ts::config::Value;

std::string RedisConfigPath;
Configuration RedisConfig; // global configuration
// SentinelDeque Sentinels;
NodeDeque ndSentinels;
NodeDeque ndSpecifics;

int RedisBlacklistLRU   = 3000;
int RedisBlacklistTime  = 60;
int RedisEvictFrequency = 1440;
int RedisCertTTL        = 720;

RedisNode *
NodeDeque::exists(std::string name)
{
  RedisNode *node                      = NULL;
  node                                 = new RedisNode();
  std::deque<RedisNode *>::iterator it = nodeDeque.begin();

  TSDebug("redis-connector", "Looking for [%s]", name.c_str());
  while (it != nodeDeque.end()) {
    // if table matches name
    // return that RedisNode *
    // node = *it;
    TSDebug("redis-connector", "Looking against %p:%s", *it, (*it)->redis_table.c_str());
    if (name == (*it)->redis_table) {
      char val1[256];
      TSDebug("redis-connector", "Defining a specific RedisConnector for %s at %s:%d %s", name.c_str(),
              (*it)->redis_ipAddr.toString(val1, sizeof(val1)), (*it)->redis_port, (*it)->redis_pass.c_str());
      // copy the element pointed to by this 'it' iterator into the newly
      // allocated 'node' and then return it!
      node->redis_table  = (*it)->redis_table;
      node->redis_ipAddr = (*it)->redis_ipAddr;
      ;
      node->redis_port = (*it)->redis_port;
      node->redis_pass = (*it)->redis_pass;

      return node;
    }
    it++;
  }
  return NULL;
}

RedisNode *
NodeDeque::ip_exists(IpAddr ip)
{
  RedisNode *node                      = NULL;
  node                                 = new RedisNode();
  std::deque<RedisNode *>::iterator it = nodeDeque.begin();

  char val1[256];
  TSDebug("redis-connector", "Looking to see if [%s] exists in the NodeDeque table", ip.toString(val1, sizeof(val1)));
  while (it != nodeDeque.end()) {
    // if table matches ip
    // return that RedisNode *
    // node = *it;
    TSDebug("redis-connector", "Looking against:%s:%s", (*it)->redis_table.c_str(),
            (*it)->redis_ipAddr.toString(val1, sizeof(val1)));
    if (ip == (*it)->redis_ipAddr) {
      TSDebug("redis-connector", "Returning the specific RedisConnector at %s:%d %s matching %s",
              (*it)->redis_ipAddr.toString(val1, sizeof(val1)), (*it)->redis_port, (*it)->redis_pass.c_str(),
              ip.toString(val1, sizeof(val1)));

      node->redis_table  = (*it)->redis_table;
      node->redis_ipAddr = (*it)->redis_ipAddr;
      ;
      node->redis_port = (*it)->redis_port;
      node->redis_pass = (*it)->redis_pass;

      return node;
    }
    it++;
  }
  return NULL;
}

void
NodeDeque::Dump_Node_Config(void)
{
  RedisNode *node                      = NULL;
  std::deque<RedisNode *>::iterator it = nodeDeque.begin();

  if (!nodeDeque.empty()) {
    TSDebug("redis-connector", "Redis Configuration:");
    while (it != nodeDeque.end()) {
      node = *it;
      char val1[256];
      if (!node->redis_table.empty()) {
        TSDebug("redis-connector", ": %s", node->redis_table.c_str());
      }
      TSDebug("redis-connector", ": %s", node->redis_ipAddr.toString(val1, sizeof(val1)));
      TSDebug("redis-connector", ": %d", node->redis_port);
      TSDebug("redis-connector", ": %s", "********");
      it++;
    }
  }
}

// void
// SentinelDeque::Dump_Node_Config(void) {
//  RedisNode *node = NULL;
//  std::deque<RedisNode *>::iterator it = sentinelDeque.begin();
//
//  if (!sentinelDeque.empty()){
//    TSDebug("redis-connector", "Redis Configuration:");
//    while (it != sentinelDeque.end()){
//      node = *it;
//      char val1[256];
//      if (!node->redis_table.empty()){
//        TSDebug("redis-connector", ": %s", node->redis_table.c_str());
//      }
//      TSDebug("redis-connector", ": %s", node->redis_ipAddr.toString(val1, sizeof(val1)));
//      TSDebug("redis-connector", ": %d", node->redis_port);
//      TSDebug("redis-connector", ": %s", "********");
//      it++;
//    }
//  }
//}

RedisConnector::RedisConnector(std::string &name, NodeDeque &sentinels_dq)
{
  cluster_name = name;
  mutex        = TSMutexCreate();

  // here we want to see if a redis node has been defined specifically for this
  // table name
  //
  // does an entry in the list of 'sentinels' exist for this table name?

  ndsentinels = sentinels_dq;
  TSDebug("redis-connector", "Building a RedisConnector: Checking if [%s] is configured", name.c_str());
  sentinel    = get_sentinel();
  master_node = ndSpecifics.exists(name);
  if (master_node == NULL) {
    // no entry defined for this name, get a sentinel and ask them for the
    // master node
    if (sentinel != NULL) {
      get_master(master_node);
    }
    // didn't get a master from a sentinel, let's try a different sentinel
    if (master_node == NULL) {
      sentinel = get_sentinel();
      if (sentinel != NULL) {
        get_master(master_node);
      }
      // We have failed miserbly get a new master node!
      if (master_node == NULL) {
        TSDebug("redis-connector", "FAILed to establish a master node.");
        return;
      }
    }
  }
  TSDebug("redis-connector", "RedisConnector contructor: master_node set to  %p", master_node);

  char val1[256];
  TSDebug("redis-connector", "Attempting to connect to new master node at %s:%d",
          master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port);
  if (!(master_node->r_ctx = master_node->r_connect())) {
    TSDebug("redis-connector",
            "Error connecting to new Redis "
            "Master Node at %s:%d",
            master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port);
  }

  // Let's set a timeout value for this context
  struct timeval tv = {1, 0};
  TSDebug("redis-connector", "Attempting to set timeout on new master node to %ld.%06ld", tv.tv_sec, (long)tv.tv_usec);
  if (redisSetTimeout(master_node->r_ctx, tv) != REDIS_OK) {
    TSDebug("redis-connector", "Error:  Can't set timeout for master_node!");
  }

  TSDebug("redis-connector", "Defined a RedisConnector for %s at %s:%d %s", cluster_name.c_str(),
          master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port, master_node->redis_pass.c_str());
}

// RedisConnector::RedisConnector(std::string &name, SentinelDeque &sentinels_dq)
//{
//
//  char val1[256];
//  sentinels = sentinels_dq;
//  sentinel = get_sentinel(sentinels);
//  TSDebug("redis-connector", "Randomly selected sentinel %s:%d",
//          sentinel->redis_ipAddr.toString(val1, sizeof(val1)),
//          sentinel->redis_port);
//
//  cluster_name = name;
//  mutex = TSMutexCreate();
//  master_node = NULL;
//
//  // Connect to the sentinel service
//  if(!(sentinel_r_ctx = sentinel->r_connect())){
//    TSDebug("redis-connector", "Error:  Can't connect to sentinel!");
//    return;
//  }
//  // Let's set a timeout value for this context
//#if 1
//  struct timeval tv = {1, 0};
////  redisSetTimeout(sentinel_r_ctx, tv);
//  if (redisSetTimeout(sentinel_r_ctx, tv) != REDIS_OK){
//    TSDebug("redis-connector", "Error:  Can't sett timeout for sentinel!");
//  }
//#endif
//
//  master_node = get_master();
//
////  if (!(master_node->r_ctx = master_node->r_connect())){
////    TSDebug("redis-connector", "Error connecting to new Redis "
////            "Master Node at %s:%d",
////            master_node->redis_ipAddr.toString(val1, sizeof(val1)),
////            master_node->redis_port);
////  }
////#if 1
////  // Let's set a timeout value for this context also
//////  redisSetTimeout(master_node->r_ctx, tv);
////  if (redisSetTimeout(master_node->r_ctx, tv) != REDIS_OK){
////    TSDebug("redis-connector", "Error:  Can't sett timeout for master_node!");
////  }
////#endif
////
////  TSDebug("redis-connector", "Defined new Redis Master Node at %s:%d",
////         master_node->redis_ipAddr.toString(val1, sizeof(val1)),
////         master_node->redis_port);
//////  }
//}

RedisConnector::~RedisConnector()
{
  TSDebug("redis-connector", "Destroying a RedisConnector for %s ", cluster_name.c_str());
  if (sentinel_r_ctx)
    redisFree(sentinel_r_ctx);
  if (master_node)
    delete master_node;
}

RedisNode *
RedisConnector::get_sentinel(void)
{
  // Pick a random sentinel index
  const int range_from = 1;
  int range_to         = 1;
  std::random_device rand_dev;
  std::mt19937 generator(rand_dev());
  std::uniform_int_distribution<int> distr(range_from, range_to);

  char val1[256];
  int rand_el = 0;
  std::deque<RedisNode *> new_sentinel_deque(ndsentinels.nodeDeque);

  // make a copy so we can do stuff to it without destroying the original
  // new_sentinel_deque = sentinels.nodeDeque;

  RedisNode *new_sentinel = NULL;
  while (new_sentinel_deque.size() > 0) {
    // adjust the random distribution to our current range based on hte deque
    // size and pick a new random number
    range_to = new_sentinel_deque.size();
    distr    = std::uniform_int_distribution<int>(range_from, range_to);
    rand_el  = distr(generator) - 1;
    TSDebug("redis-connector", "Random number to access the deque of sentinels: %d", rand_el);

    new_sentinel = reinterpret_cast<RedisNode *>(new_sentinel_deque.at(rand_el));

    // Connect to the sentinel service and set the context
    TSDebug("redis-connector", "Attempting to connect to randomly selected Sentinel at %s:%d",
            new_sentinel->redis_ipAddr.toString(val1, sizeof(val1)), new_sentinel->redis_port);
    if (!(sentinel_r_ctx = new_sentinel->r_connect())) {
      TSDebug("redis-connector", "Error:  Can't connect to sentinel!");
      new_sentinel_deque.erase(new_sentinel_deque.begin() + rand_el);
      continue;
    }

    // Let's set a timeout value for this context
    struct timeval tv = {1, 0};
    TSDebug("redis-connector", "Attempting to set timeout on new Sentinel to %ld.%06ld", tv.tv_sec, (long)tv.tv_usec);
    if (redisSetTimeout(sentinel_r_ctx, tv) != REDIS_OK) {
      TSDebug("redis-connector", "Error:  Can't set timeout for sentinel!");
      new_sentinel_deque.erase(new_sentinel_deque.begin() + rand_el);
      continue;
    }

    // PING the new sentinel to make sure it is alive
    void *r             = redisCommand(sentinel_r_ctx, "PING");
    redisReply *r_reply = reinterpret_cast<redisReply *>(r);

    if (!r_reply || sentinel_r_ctx->err) {
      TSDebug("redis-connector", "Error: Sentinel FAILED to respond to PING "
                                 "command!");
      new_sentinel_deque.erase(new_sentinel_deque.begin() + rand_el);
      continue;
    } else {
      TSDebug("redis-connector", "Sentinel responded to PING command!");
      break;
    }
  }

  if (new_sentinel != NULL) {
    TSDebug("redis-connector", "Defined new Sentinel Node at %s:%d", new_sentinel->redis_ipAddr.toString(val1, sizeof(val1)),
            new_sentinel->redis_port);
  } else {
    TSDebug("redis-connector", "FAILED to define new Sentinel Node");
  }

  // Now let's look up this sentinel node in the original table of sentinels so
  // it persists
  return ndSpecifics.ip_exists(new_sentinel->redis_ipAddr);

  // return new_sentinel;
}

// RedisNode *
// RedisConnector::get_sentinel(SentinelDeque &sentinels)
//{
//  // Pick a random sentinel index
//  int rand_el = rand() % (int)(sentinels.sentinelDeque.size());
//  TSDebug("redis-connector", "Random number to access the deque of sentinels: %d", rand_el);
//
//  return (reinterpret_cast<RedisNode *>(sentinels.sentinelDeque.at(rand_el)));
//}

RedisNode *
RedisConnector::get_master(RedisNode *new_master_node)
{
  TSDebug("redis-connector-get-master", "Requesting %s master node from sentinel", cluster_name.c_str());

  TSDebug("redis-connector-get-master",
          "While requesting a new master node from sentinel, this->master_node = %p and master_node = %p", this->master_node,
          master_node);

  TSDebug("redis-connector-get-master", "While requesting a new master node from sentinel, sentinel = %p and sentinel_r_ctx = %p",
          sentinel, sentinel_r_ctx);

  // if master_node is already defined, delete it and let's create a new node
  if (this->master_node != NULL) {
    delete this->master_node;
  }

  // no entry defined for this name, get a sentinel and ask them for the
  // master node
  TSDebug("redis-connector-get-master", "Master_node is not yet set.");
  if (sentinel != NULL) {
    TSDebug("redis-connector-get-master", "Using existing sentinel to ask for a new master_node.");
    get_master_from_sentinel(this->master_node);
  }
  // We tried the configured sentinel and failed, let's get a new sentinel and try again
  if (this->master_node == NULL) {
    TSDebug("redis-connector-get-master", "Master_node is not still not set, getting a new sentinel config.");
    sentinel = get_sentinel();
    if (sentinel != NULL) {
      TSDebug("redis-connector-get-master", "Obtained a new sentinel config at %p, requesting new master_node", sentinel);
      get_master_from_sentinel(this->master_node);
    }

    if (this->master_node == NULL) {
      TSDebug("redis-connector-get-master", "Still don't have a master_node from sentinels, going back to specific local "
                                            "master_node configuration and giving up on sentinels for now");
      this->master_node = ndSpecifics.exists(this->cluster_name);
      if (this->master_node == NULL) {
        TSDebug("redis-connector-get-master", "FAILed to establish a master node.");
        return (this->master_node);
      }
    }
  }

  if (this->master_node != NULL) {
    TSDebug("redis-connector", "RedisConnector get_master(): master_node set to  %p", this->master_node);
    return (this->master_node);
    ;
  }

  TSDebug("redis-connector", "RedisConnector get_master(): setting master_node FAILed");
  return NULL;
}

//  if (sentinel_r_ctx == NULL) {
//    ndsentinels = sentinels_dq;
//    TSDebug("redis-connector", "No sentinel connected, getting new sentinel");
//    get_sentinel
//    master_node = ndSpecifics.exists(name);
//    if (master_node == NULL) {
//    TSDebug("redis-connector", "Unable to get_master(): No sentinel has been connected for %s",
//            cluster_name.c_str());
//    return NULL;
//  }

RedisNode *
RedisConnector::get_master_from_sentinel(RedisNode *new_master_node)
{
  // Query the sentinel for the master node IP and port for this database
  void *r             = redisCommand(sentinel_r_ctx, "SENTINEL get-master-addr-by-name %s", cluster_name.c_str());
  redisReply *r_reply = reinterpret_cast<redisReply *>(r);

  if (!r_reply || sentinel_r_ctx->err) {
    TSDebug("redis-connector", "Error:  Can't execute get-master-addr-by-name "
                               "command!");
    if (r_reply)
      freeReplyObject(r_reply);
    return NULL;
  }

  if (r_reply->type != REDIS_REPLY_ARRAY) {
    TSDebug("redis-connector", "Not an array!");
  }

  for (size_t i = 0; i < r_reply->elements; i += 2) {
    redisReply *r_ip, *r_port;

    r_ip = r_reply->element[i];
    if (r_ip->type != REDIS_REPLY_STRING) {
      TSDebug("redis-connector", "Error:  Invalid master IP reply!");
      if (r_reply)
        freeReplyObject(r_reply);
      return NULL;
    }
    r_port = r_reply->element[i + 1];
    if (r_port->type != REDIS_REPLY_STRING) {
      TSDebug("redis-connector", "Error:  Invalid master Port reply!");
      if (r_reply)
        freeReplyObject(r_reply);
      return NULL;
    }

    // Now let's store this master node info

    new_master_node = new RedisNode();
    new_master_node->redis_ipAddr.load(r_ip->str);
    new_master_node->redis_port = atoi(r_port->str);
    new_master_node->redis_pass = sentinel->redis_pass;
  }

  char val1[256];
  TSDebug("redis-connector", "Defined new Redis Master Node at %s:%d", new_master_node->redis_ipAddr.toString(val1, sizeof(val1)),
          new_master_node->redis_port);

  if (r_reply)
    freeReplyObject(r_reply);
  return new_master_node;
}

// RedisNode *
// RedisConnector::get_master(void)
//{
//  TSDebug("redis-connector", "Requesting %s master node from sentinel",
//          cluster_name.c_str());
//
//  // Query the sentinel for the master node IP and port for this database
//  void *r = redisCommand(sentinel_r_ctx, "SENTINEL get-master-addr-by-name %s",
//                         cluster_name.c_str());
//  redisReply *r_reply = reinterpret_cast<redisReply *>(r);
//
//  if (!r_reply || sentinel_r_ctx->err) {
//    TSDebug("redis-connector", "Error:  Can't execute get-master-addr-by-name "
//            "command!");
//    return NULL;
//  }
//
//  if (r_reply->type != REDIS_REPLY_ARRAY) {
//    TSDebug("redis-connector", "Not an array!");
//  }
//
//  for (size_t i = 0; i < r_reply->elements; i+=2) {
//    redisReply *r_ip, *r_port;
//
//    r_ip = r_reply->element[i];
//    if (r_ip->type != REDIS_REPLY_STRING) {
//        TSDebug("redis-connector", "Error:  Invalid master IP reply!");
//        return NULL;
//    }
//    r_port = r_reply->element[i+1];
//    if (r_port->type != REDIS_REPLY_STRING) {
//        TSDebug("redis-connector", "Error:  Invalid master Port reply!");
//        return NULL;
//    }
//
//    // Now let's store this master node info
//    master_node = new RedisNode();
//    master_node->redis_ipAddr.load(r_ip->str);
//    master_node->redis_port = atoi(r_port->str);
//    master_node->redis_pass = sentinel->redis_pass;
//  }
//
//  char val1[256];
//  if (!(master_node->r_ctx = master_node->r_connect())){
//    TSDebug("redis-connector", "Error connecting to new Redis "
//            "Master Node at %s:%d",
//            master_node->redis_ipAddr.toString(val1, sizeof(val1)),
//            master_node->redis_port);
//  }
//
//  // Let's set a timeout value for this context
//  struct timeval tv = {1, 0};
//  if (redisSetTimeout(master_node->r_ctx, tv) != REDIS_OK){
//    TSDebug("redis-connector", "Error:  Can't sett timeout for master_node!");
//  }
//
//  TSDebug("redis-connector", "Defined new Redis Master Node at %s:%d",
//         master_node->redis_ipAddr.toString(val1, sizeof(val1)),
//         master_node->redis_port);
//
//  return master_node;
//}

redisContext *
RedisNode::r_connect(void)
{
  char val1[256];
  // Connect to the service
  TSDebug("redis-connector", "Connecting to %s:%d", this->redis_ipAddr.toString(val1, sizeof(val1)), this->redis_port);
  r_ctx = redisConnect(this->redis_ipAddr.toString(val1, sizeof(val1)), this->redis_port);
  if (!r_ctx || r_ctx->err) {
    if (r_ctx)
      redisFree(r_ctx);
    TSDebug("redis-connector", "Error:  Can't connect to service!");
    return NULL;
  }
  return (r_ctx);
}

void *
RedisNode::r_send(redisReply *&r_reply, const char *format, ...)
{
  TSDebug("redis-connector", "Top");
  va_list arg_list;
  va_start(arg_list, format);

  char request[2048];
  const size_t needed = vsnprintf(request, sizeof request, format, arg_list) + 1;
  if (needed > sizeof request) {
    TSDebug("redis-connector", "Error: Request exceeds buffer capacity "
                               "- command not sent");
    va_end(arg_list);
    return (void *)NULL;
  }
  va_end(arg_list);
  TSDebug("redis-connector", "Middle");

  char val1[256];
  if (strstr(request, "AUTH")) { // If this is an AUTH command, redact password
    TSDebug("redis-connector", "Sending [AUTH <********>] to %s:%d", this->redis_ipAddr.toString(val1, sizeof(val1)),
            this->redis_port);
  } else {
    TSDebug("redis-connector", "Sending [%s] to %s:%d", request, this->redis_ipAddr.toString(val1, sizeof(val1)), this->redis_port);
  }
  TSDebug("redis-connector", "Before redisCommand");
  void *r = redisCommand(this->r_ctx, request);
  TSDebug("redis-connector", "Before reinterpret_cast");
  r_reply = reinterpret_cast<redisReply *>(r);
  TSDebug("redis-connector", "Before returning");
  return r;
}

int
RedisConnector::auth(redisReply *&r_reply, std::string servicename)
{
  int retries       = 1; // hard coded for now to only retry once, may add a config
  int second_chance = 2; // hard coded for now to only retry once, may add a config
  char val1[256];
  TSDebug("redis-connector", "AUTHing %s on %s:%d", servicename.c_str(), master_node->redis_ipAddr.toString(val1, sizeof(val1)),
          master_node->redis_port);

  while (retries >= 0 && second_chance >= 0) {
    if (master_node->r_send(r_reply, "AUTH %s", master_node->redis_pass.c_str())) {
      if (r_reply->type == REDIS_REPLY_STATUS && (strcasecmp(r_reply->str, "OK") == 0)) {
        TSDebug("redis-connector", "Redis %s AUTH successfully returned [%s]!", servicename.c_str(), r_reply->str);
        break;
      } else {
        TSDebug("redis-connector", "Redis %s AUTH FAILED with type:%d:%s!", servicename.c_str(), r_reply->type, r_reply->str);
      }
    } else {
      TSDebug("redis-connector", "Redis %s AUTH FAILED with %d:%s! Attempting to get another master node", servicename.c_str(),
              r_reply->type, r_reply->str);
      //      TSMutexLock(mutex);
      //      RedisNode *old_master_node, *new_master_node;
      //      old_master_node = master_node;
      get_master(master_node);
      //      new_master_node = get_master();
      //      master_node = new_master_node;
      //      delete old_master_node;

      if (!(master_node->r_ctx = master_node->r_connect())) {
        TSDebug("redis-connector",
                "Error connecting to new Redis "
                "Master Node at %s:%d",
                master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port);
      }

      if (master_node->r_ctx && (this->auth(r_reply, this->cluster_name) == REDIS_OK)) {
        TSDebug("redis-connector", "Redis %s re-authenticated successfully!", this->cluster_name.c_str());
      }

      //      TSMutexUnlock(mutex);
      second_chance--; // let's give ourselves another try with this new master node
    }
    retries--;
  }

  return (r_reply ? r_reply->type : REDIS_REPLY_ERROR);
}

int
RedisConnector::get(redisReply *&r_reply, std::string servicename, const char *key)
{
  int retries       = 1; // hard coded for now to only retry once, may add a config
  int second_chance = 1; // hard coded for now to only retry once, may add a config
  char val1[256];
  TSDebug("redis-connector", "GETting %s for [%s] from %s:%d", servicename.c_str(), key,
          master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port);
  while (retries >= 0 && second_chance >= 0) {
    if (master_node->r_send(r_reply, "GET %s", key)) {
      //  TSDebug("redis-connector", "GETting %s for [%s]", servicename.c_str(), key);
      //  while (retries >= 0){
      //    if (master_node) {
      //      TSDebug("redis-connector", "before r_send GETting %s for [%s] master_node = %p", servicename.c_str(), key,
      //      master_node);
      //    } else {
      //      TSDebug("redis-connector", "before r_send GETting %s for [%s] master_node = NULL", servicename.c_str(), key);
      //    }
      //    if (master_node && master_node->r_send(r_reply, "GET %s", key)){
      //      TSDebug("redis-connector", "after r_send GETting %s for [%s]", servicename.c_str(), key);
      if (r_reply->type == REDIS_REPLY_STRING) {
        TSDebug("redis-connector", "Redis %s GET %s successfully returned [%s]!", servicename.c_str(), key, r_reply->str);
        break; // got what we waned
      } else if (r_reply->type == REDIS_REPLY_NIL) {
        TSDebug("redis-connector", "Redis %s GET %s NOT FOUND!", servicename.c_str(), key);
        break;
      }
    } else {
      TSDebug("redis-connector", "Redis %s GET %s FAILED with %d:%s! Attempting to get a new master node", servicename.c_str(), key,
              r_reply->type, r_reply->str);
      //      TSMutexLock(mutex);
      //      RedisNode *old_master_node, *new_master_node;
      //      old_master_node = master_node;
      //      new_master_node = get_master();
      get_master(master_node);
      //      master_node = new_master_node;
      //      delete old_master_node;

      if (!(master_node->r_ctx = master_node->r_connect())) {
        TSDebug("redis-connector",
                "Error connecting to new Redis "
                "Master Node at %s:%d",
                master_node->redis_ipAddr.toString(val1, sizeof(val1)), master_node->redis_port);
      }

      if (master_node->r_ctx && (this->auth(r_reply, this->cluster_name) == REDIS_OK)) {
        TSDebug("redis-connector", "Redis %s re-authenticated successfully!", this->cluster_name.c_str());
      }

      //      TSMutexUnlock(mutex);
      second_chance--; // let's give ourselves another try with this new master node
    }
    retries--;
  }

  return (r_reply ? r_reply->type : REDIS_REPLY_ERROR);
}

int
RedisNode::exists(redisReply *&r_reply, std::string servicename, const char *key)
{
  TSDebug("redis-connector", "EXISTS %s %s", servicename.c_str(), key);
  if (r_send(r_reply, "EXISTS %s %s", servicename.c_str(), key) == REDIS_OK) {
    if (r_reply->type == REDIS_REPLY_INTEGER) {
      TSDebug("redis-connector", "Redis domain_map EXISTS %s %s returned [%s]!", servicename.c_str(), key,
              r_reply->integer ? "YES" : "NO");
    }
  }
  return r_reply->type;
}

// lets check the allowed_domains set
// in redis to make sure we should even try to load this guy's cert
int
RedisNode::sismember(redisReply *&r_reply, std::string servicename, const char *setkey)
{
  if (r_send(r_reply, "SISMEMBER %s %s", servicename.c_str(), setkey)) {
    if (r_reply->type == REDIS_REPLY_INTEGER) {
      TSDebug("redis-connector", "Redis %s SISMEMBER %s returned [%s]!", servicename.c_str(), setkey,
              r_reply->integer ? "YES" : "NO");
    }
  }
  return r_reply->type;
}

int
RedisNode::get_resp_simple_str(redisReply *reply)
{
  void *_reply;
  int ret           = REDIS_ERR;
  struct timeval tv = {0, 1000};
  if (redisSetTimeout(this->r_ctx, tv) == REDIS_OK) {
    while ((ret = redisGetReply(this->r_ctx, &_reply)) == REDIS_OK) {
      if (strcasecmp(reply->str, "OK") == 0) {
        TSDebug("redis-connector", "Success:  Redis returned [%s]", reply->str);
      } else {
        TSDebug("redis-connector", "Error:  Redis returned [%s]", reply->str);
      }
    }
  }
  freeReplyObject(reply);
  return ret;
}

int
Load_Redis_Config_File(void)
{
  ts::Rv<Configuration> cv = Configuration::loadFromPath(RedisConfigPath.c_str());

  if (!cv.isOK()) {
    char error_buffer[1024];
    cv._errata.write(error_buffer, sizeof(error_buffer), 0, 0, 0, "");
    return -1;
  }
  RedisConfig = cv;

  return 1;
}

void
Parse_Redis_Rules(Value &parent, RedisNode &orig_values)
{
  for (size_t i = 0; i < parent.childCount(); i++) {
    Value child = parent[i];
    Parse_Redis_Config(child, orig_values);
  }
}

void
Parse_Redis_Local_Rules(Value &parent, RedisNode &orig_values)
{
  for (size_t i = 0; i < parent.childCount(); i++) {
    Value child = parent[i];
    Parse_Redis_Local_Config(child, orig_values);
  }
}

void
Parse_Redis_Config(Value &parent, RedisNode &orig_values)
{
  RedisNode *cur_values = NULL;
  cur_values            = new RedisNode();

  Value val = parent.find("redis_sentinel");
  if (val) {
    TSDebug("redis-connector", "Configuring \"redis_sentinel\" with %s", val.getText()._ptr);
    cur_values->redis_ipAddr.load(val.getText());
  }

  val = parent.find("redis_sentinel_port");
  if (val.hasValue()) {
    TSDebug("redis-connector", "Configuring \"redis_sentinel_port\" with %s", val.getText()._ptr);
    cur_values->redis_port = atoi(val.getText()._ptr);
  }

  val = parent.find("redis_pass");
  if (val) {
    TSDebug("redis-connector", "Configuring \"redis_pass\" ");
    cur_values->redis_pass = std::string(val.getText()._ptr, val.getText()._size);
  }

  val = parent.find("child_match");
  if (val) {
    // Parse_NewRedis_Rules(val, cur_values);
  } else {
    // We are terminal, let's push this sentinel config into the deque
    char val1[256];
    TSDebug("redis-connector",
            "Terminal Redis Config: redis_sentinel [%s], "
            "redis_port [%d], "
            "redis_pass [<***>]",
            cur_values->redis_ipAddr.toString(val1, sizeof(val1)), cur_values->redis_port);
    // Sentinels.sentinelDeque.push_back(cur_values);
    ndSentinels.nodeDeque.push_back(cur_values);
  }
}

void
Parse_Redis_Local_Config(Value &parent, RedisNode &orig_values)
{
  RedisNode *cur_values = NULL;
  cur_values            = new RedisNode();

  Value val = parent.find("redis_local_table");
  if (val) {
    TSDebug("redis-connector", "Configuring \"redis_local_table\" %s", val.getText()._ptr);
    cur_values->redis_table = std::string(val.getText()._ptr, val.getText()._size);
  }

  val = parent.find("redis_local_ip");
  if (val) {
    TSDebug("redis-connector", "Configuring \"redis_local_ip\" with %s", val.getText()._ptr);
    cur_values->redis_ipAddr.load(val.getText());
  }

  val = parent.find("redis_local_port");
  if (val.hasValue()) {
    TSDebug("redis-connector", "Configuring \"redis_local_port\" with %s", val.getText()._ptr);
    cur_values->redis_port = atoi(val.getText()._ptr);
  }

  val = parent.find("redis_local_pass");
  if (val) {
    TSDebug("redis-connector", "Configuring \"redis_local_pass\" ");
    cur_values->redis_pass = std::string(val.getText()._ptr, val.getText()._size);
  }

  val = parent.find("child_match");
  if (val) {
    // Parse_NewRedis_Rules(val, cur_values);
  } else {
    // We are terminal, let's push this node config into the deque
    char val1[256];
    TSDebug("redis-connector",
            "Terminal Redis Config: redis [%s], "
            "redis_local_ip [%s], "
            "redis_local_port [%d], "
            "redis__local_pass [<***>]",
            cur_values->redis_table.c_str(), cur_values->redis_ipAddr.toString(val1, sizeof(val1)), cur_values->redis_port);
    ndSpecifics.nodeDeque.push_back(cur_values);
  }
}

int
Load_Redis_Configuration(void)
{
  int ret = Load_Redis_Config_File();

  if (ret < 0) {
    return -1;
  }

  Value root = RedisConfig.getRoot();
  Value val  = root["redis_blacklist_lru"];
  if (val.isLiteral()) {
    TSDebug("redis-connector", "Configuring \"redis_blacklist_lru\" with %s", val.getText()._ptr);
    RedisBlacklistLRU = std::stoi(std::string(val.getText()._ptr, val.getText()._size));
  }

  val = root["redis_blacklist_time"];
  if (val.isLiteral()) {
    TSDebug("redis-connector", "Configuring \"redis_blacklist_time\" with %s", val.getText()._ptr);
    RedisBlacklistTime = std::stoi(std::string(val.getText()._ptr, val.getText()._size));
  }

  val = root["redis_evict_freq"];
  if (val.isLiteral()) {
    TSDebug("redis-connector", "Configuring \"redis_evict_freq\" with %s minutes", val.getText()._ptr);
    RedisEvictFrequency = std::stoi(std::string(val.getText()._ptr, val.getText()._size));
  }

  val = root["redis_cert_ttl"];
  if (val.isLiteral()) {
    TSDebug("redis-connector", "Configuring \"redis_cert_ttl\" with %s minutes", val.getText()._ptr);
    RedisCertTTL = std::stoi(std::string(val.getText()._ptr, val.getText()._size));
  }

  val = root["redis_local"];
  if (val.isContainer()) {
    RedisNode values;
    Parse_Redis_Local_Rules(val, values);
  }

  val = root["redis_sentinels"];
  if (val.isContainer()) {
    RedisNode values;
    Parse_Redis_Rules(val, values);
  }

  val = root["redis"];
  if (val.isContainer()) {
    RedisNode values;
    Parse_Redis_Rules(val, values);
  }

  // Sentinels.Dump_Node_Config();
  ndSentinels.Dump_Node_Config();
  ndSpecifics.Dump_Node_Config();

  return ret;
}
