/*
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

#include <ts/ts.h>
#include <ts/remap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

// global settings
static const char *PLUGIN_NAME = "redis_remap";

// redis related global variables
redisContext *r_ctx;

// char *
// redis_get()
// {
//   char get_str[1024];
//   redisReply *reply;
//
//   snprintf(get_str, 1028, "GET %s", key);
//   TSDebug(PLUGIN_NAME, "querying redis with [%s]\n", get_str);
//   reply = redisCommand(ctx, get_str);
//   if ((reply != NULL) && (reply->type) == REDIS_REPLY_STATUS){
//     TSDebug(PLUGIN_NAME, "redis replied with [%s] and length [%d]\n",
// reply->str reply->len);
//   }
//   else {
//     TSError("[%s]: redis query failed and returned [%d]\n", PLUGIN_NAME);
//   }
//
//   freeReplyObject(reply);
// }

bool do_redis_remap(TSCont contp, TSHttpTxn txnp) {
  TSMBuffer reqp;
  TSMLoc hdr_loc, url_loc, field_loc;
  bool ret_val = false;

  const char *request_host;
  int request_host_length = 0;
  const char *request_scheme;
  int request_scheme_length = 0;
  int request_port = 80;
  char get_key[1024];

  if (TSHttpTxnClientReqGet((TSHttpTxn)txnp, &reqp, &hdr_loc) != TS_SUCCESS) {
    TSDebug(PLUGIN_NAME, "could not get request data");
    return false;
  }

  if (TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc) != TS_SUCCESS) {
    TSDebug(PLUGIN_NAME, "couldn't retrieve request url");
    goto release_hdr;
  }

  field_loc =
      TSMimeHdrFieldFind(reqp, hdr_loc, TS_MIME_FIELD_HOST, TS_MIME_LEN_HOST);

  if (!field_loc) {
    TSDebug(PLUGIN_NAME, "couldn't retrieve request HOST header");
    goto release_url;
  }

  request_host = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, field_loc, -1,
                                              &request_host_length);
  if (request_host == NULL || strlen(request_host) < 1) {
    TSDebug(PLUGIN_NAME, "couldn't find request HOST header");
    goto release_field;
  }

  request_scheme = TSUrlSchemeGet(reqp, url_loc, &request_scheme_length);
  request_port = TSUrlPortGet(reqp, url_loc);

  TSDebug(PLUGIN_NAME, "      +++++REDIS REMAP+++++      ");

  TSDebug(PLUGIN_NAME, "\nINCOMING REQUEST ->\n ::: from_scheme_desc: %.*s\n "
                       "::: from_hostname: %.*s\n ::: from_port: %d",
          request_scheme_length, request_scheme, request_host_length,
          request_host, request_port);

  snprintf(get_key, 1024, "GET %.*s://%.*s:%d/", request_scheme_length,
           request_scheme, request_host_length, request_host, request_port);

  //
  // This is where redis comes in
  //
  // TODO This doesn't support wildcard, aka regex_map, mappin4gs.
  //

  redisReply *redis_reply;

  char oscheme[1024], ohost[1024];
  int oport;

  TSDebug(PLUGIN_NAME, "querying redis with [%s]\n", get_key);
  redis_reply = (redisReply *)redisCommand(r_ctx, get_key);

  if ((redis_reply != NULL) && (redis_reply->type == REDIS_REPLY_STATUS)) {
    TSDebug(PLUGIN_NAME, "redis replied with [%s] and length [%d]\n",
            redis_reply->str, redis_reply->len);
    TSDebug(PLUGIN_NAME, "got the response from server : %s\n",
            redis_reply->str);
    TSDebug(PLUGIN_NAME, "scanf result : %d\n",
            sscanf(redis_reply->str, "%[a-zA-Z]://%[^:]:%d", oscheme, ohost,
                   &oport));
    if (sscanf(redis_reply->str, "%[a-zA-Z]://%[^:]:%d", oscheme, ohost,
               &oport) == 3) {
      TSDebug(PLUGIN_NAME, "\nOUTGOING REQUEST ->\n ::: to_scheme_desc: %s\n "
                           "::: to_hostname: %s\n ::: to_port: %d",
              oscheme, ohost, oport);
      TSMimeHdrFieldValueStringSet(reqp, hdr_loc, field_loc, 0, ohost, -1);
      TSUrlHostSet(reqp, url_loc, ohost, -1);
      TSUrlSchemeSet(reqp, url_loc, oscheme, -1);
      TSUrlPortSet(reqp, url_loc, oport);
      ret_val = true;
    } else {
      goto not_found;
    }
  } else if ((redis_reply != NULL) && (redis_reply->type == REDIS_REPLY_NIL)) {
    TSDebug(PLUGIN_NAME, "[%s] not found in redis", get_key);
    goto not_found;
  } else {
    TSDebug(PLUGIN_NAME,
            "didn't get any response from redis, returned [%d - %s]\n",
            redis_reply->type, redis_reply->str);
    goto not_found;
  }

  ret_val = true; // be sure to skip the not_found 404 return

not_found:
  // lets build up a nice 404 message for someone
  if (!ret_val) {
    TSHttpHdrStatusSet(reqp, hdr_loc, TS_HTTP_STATUS_NOT_FOUND);
    TSHttpTxnSetHttpRetStatus(txnp, TS_HTTP_STATUS_NOT_FOUND);
  }
free_stuff:
  if (redis_reply)
    freeReplyObject(redis_reply);
release_request:
#if (TS_VERSION_NUMBER < 2001005)
  if (request_host)
    TSHandleStringRelease(reqp, hdr_loc, request_host);
  if (request_scheme)
    TSHandleStringRelease(reqp, hdr_loc, request_scheme);
#endif
release_field:
  if (field_loc)
    TSHandleMLocRelease(reqp, hdr_loc, field_loc);
release_url:
  if (url_loc)
    TSHandleMLocRelease(reqp, hdr_loc, url_loc);
release_hdr:
  if (hdr_loc)
    TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);

  return ret_val;
}

static int redis_remap(TSCont contp, TSEvent event, void *edata) {
  TSHttpTxn txnp = (TSHttpTxn)edata;
  TSEvent reenable = TS_EVENT_HTTP_CONTINUE;

  if (event == TS_EVENT_HTTP_READ_REQUEST_HDR) {
    TSDebug(PLUGIN_NAME, "Reading Request");
    TSSkipRemappingSet(txnp, 1);
    if (!do_redis_remap(contp, txnp)) {
      reenable = TS_EVENT_HTTP_ERROR;
    }
  }

  TSHttpTxnReenable(txnp, reenable);
  return 1;
}

void TSPluginInit(int argc, const char *argv[]) {
  TSPluginRegistrationInfo info;
  // FILE *fp;
  // char servers_string[8192];

  info.plugin_name = const_cast<char *>(PLUGIN_NAME);
  info.vendor_name = const_cast<char *>("Apache Software Foundation");
  info.support_email = const_cast<char *>("dev@trafficserver.apache.org");

  TSDebug(PLUGIN_NAME, "about to init redis\n");
  if (TS_SUCCESS != TSPluginRegister(TS_SDK_VERSION_2_0, &info)) {
    TSError("[%s]: plugin registration failed.\n", PLUGIN_NAME);
    return;
  }

// parse the configuration file
// TODO: this is still under testing 1.0.2 version should have this feature
/*
if(argc < 1) {
    TSError("redis_remap: you should pass a configuration file as argument to
plugin with list of servers.\n");
    return;
}

fp = fopen(argv[0], "r");
if(!fp) {
    TSError("redis_remap: Failed to open the configuration file %s\n", argv[0]);
    return;
}

while(!feof(fp)) {
    fscanf(fp,"servers=%[^\n] ", servers_string);
}

fclose(fp);
*/

// initialize the memcache
// fp = NULL;
// snprintf(servers_string, 1,"%c",'h');
////r_server = redis_create(NULL);

#define MAX_HOST_LEN 128

  const char *default_host = "localhost";
  char redis_host[MAX_HOST_LEN];
  int redis_port = 6379;
  snprintf(redis_host, MAX_HOST_LEN, "%s", default_host);

  r_ctx = redisConnect(redis_host, redis_port);
  if (r_ctx->err) {
    TSError(
        "[%s]: plugin registration failed while connecting to redis server.\n",
        PLUGIN_NAME);
    return;
  } else {
    TSDebug(PLUGIN_NAME, "redis connection successfully initialized");
  }

  TSCont cont = TSContCreate(redis_remap, TSMutexCreate());

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, cont);

  TSDebug(PLUGIN_NAME, "plugin is successfully initialized [plugin mode]");
  return;
}
