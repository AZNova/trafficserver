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
#include <map>
#include <ts/ts.h>
#include <tsconfig/TsValue.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <getopt.h>
#include "domain-tree.h"
#include "redis-connector.h"
#include "stats.h"

#include "tscore/ink_hrtime.h"

#include "ssl-utils.h"
#include "sslentry.h"

using ts::config::Configuration;
using ts::config::Value;

#define PN "ssl-lazy-loader"
#define PCP "[" PN " Plugin] "

namespace
{
class CertLookup
{
public:
  DomainNameTree tree;
  IpMap ipmap; // for non-SNI certs, not used in this version
} Lookup;

std::string ConfigPath;
Configuration Config; // global configuration

class NetVCDeque
{
public:
  std::deque<TSVConn> netvcDeque;
  TSMutex mutex;

  NetVCDeque() { mutex = TSMutexCreate(); }
};

// TSCont expiry_cont;

struct ParsedSslValues {
  std::string server_priv_key_file;
  std::string server_name;
  std::string server_cert_name;
  std::string action;
  IpRangeQueue server_ips;
};

//  Random TODO notes:
//  - change the expiry to use a FIFO deque
//  --- push_back nex entries on load
//  --- at the expiry cycle, check front entry's date
//  --- if the cert is ready to be evicted, remove it and pop it off the front
//  --- check the next front cert
//  --- once front entry's date is no longer ready to be evicted,
//  ------ we're done wit this expiry cycle.
//  --- this means no need to traverse the entire domain_tree lookup
//
//  - clean up some of hte TSDebug messages so they make more sense (tags)
//
//  - implement plugin messaging from the command line
//  --- traffic_ctl plugin
//  --- TS_LIFECYCLE_MSG_HOOK
//  --- "is a cert for domain.com loaded?"

void
fetch_names(X509 *cert, std::deque<std::string> &names)
{
  // Fetch out the names associated with the certificate
  if (cert != NULL) {
    TSDebug(PN, "OK, we have the cert loaded, let's pull out the names");
    X509_NAME *name = X509_get_subject_name(cert);
    char subjectCn[256];

    if (X509_NAME_get_text_by_NID(name, NID_commonName, subjectCn, sizeof(subjectCn)) >= 0) {
      TSDebug(PN, "Found [%s] as the Common Name", subjectCn);
      std::string tmp_name(subjectCn);
      names.push_back(tmp_name);
    }
    // Look for alt names
    GENERAL_NAMES *alt_names = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (alt_names) {
      unsigned count = sk_GENERAL_NAME_num(alt_names);
      for (unsigned i = 0; i < count; i++) {
        GENERAL_NAME *alt_name = sk_GENERAL_NAME_value(alt_names, i);

        if (alt_name->type == GEN_DNS) {
          // Current name is a DNS name, let's check it
          char *name_ptr = (char *)ASN1_STRING_data(alt_name->d.dNSName);
          std::string tmp_name(name_ptr);
          TSDebug(PN, "Found [%s] as an Subject Alt Name", tmp_name.c_str());
          names.push_back(tmp_name);
        }
      }
      sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
    }
  }
}

SSL_CTX *
Load_Certificate_From_Memory(SslEntry *&entry, std::deque<std::string> &names, std::string &cert_buffer)
{
  SSL_CTX *ctx = NULL;
  X509 *cert   = NULL;
  //  EVP_PKEY *key       = NULL;

  if (entry->redis_CN.length() > 0) {
    TSDebug(PN, "Loading cert for [%s]", entry->redis_CN.c_str());
    BIO *cbio = BIO_new_mem_buf((void *)cert_buffer.c_str(), -1);
    cert      = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    /*
        if (SSL_CTX_use_certificate(ctx, cert) < 1) {
          TSDebug(PN, "Failed to apply cert %s", entry->redis_CN.c_str());
          SSL_CTX_free(ctx);
          BIO_free(cbio);
          return NULL;
        }
        key = PEM_read_bio_PrivateKey(cbio, NULL, NULL, NULL);
        if (SSL_CTX_use_PrivateKey(ctx, key) < 1) {
          TSDebug(PN, "Failed to apply key %s", entry->redis_CN.c_str());
          SSL_CTX_free(ctx);
          BIO_free(cbio);
          return NULL;
        }
     */
    BIO_free(cbio);
  } else {
    TSDebug(PN, "Failed to load cert from memory for %s", entry->redis_CN.c_str());
    return NULL;
  }

  if (cert != NULL) {
    TSDebug(PN, "OK, we have the cert loaded, let's pull out the names");
    // Fetch out the names associated with the certificate
    fetch_names(cert, names);

    // set the load time and last access time
    entry->set_load_time(time(0));
    entry->set_access_time(time(0));

    const char *cc_cn   = names.front().c_str();
    TSSslContext ctxobj = TSSslServerContextCreate(reinterpret_cast<TSSslX509>(cert), cc_cn);
    ctx                 = reinterpret_cast<SSL_CTX *>(ctxobj);
  }

  // Do we need to free cert? Did assigning to SSL_CTX increment its ref count
  return ctx;
}

// int Parse_order = 0;

std::string crt_c_name = "ssl_cert_map";
std::string dom_c_name = "ssl_domain_map";

/* Structure to be associated to cert load requests */
typedef struct {
  int freq_multiplier;
  int thread_initialized;
  // RedisConnector *sd_cert_map;
  // RedisConnector *sd_domain_map;
  RedisConnector *nd_cert_map;
  RedisConnector *nd_domain_map;
  SslEntry *entry;
} LoaderData;

///* Structure to be associated to cert load requests */
// typedef struct {
//  int thread_initialized;
//  TSCont loader_cont;
//} ReqData;

// thread_local ReqData thread_req_data;
thread_local LoaderData thread_loader_data;

//
// check the cert deque to see if certs have been in memory long enough that
// it needs to be removed from the deque
//
// static int
// Expiry_Thread(TSCont cont, TSEvent event ATS_UNUSED, void *arg)
//{
//  ink_hrtime expiry_thread_sched_ms = RedisEvictFrequency * 60 * 1000;
//  TSDebug("ssl-lazy-expiry", "Expiring certs");
//  Lookup.tree.expire(RedisCertTTL * 60);
//  TSDebug("ssl-lazy-expiry", "Rescheduling cert expiry thread for %d minutes "
//          "with a Cert TTL of %d minutes",
//          RedisEvictFrequency, RedisCertTTL);
//  TSContSchedule(expiry_cont, expiry_thread_sched_ms, TS_THREAD_POOL_TASK);
//  return 1;
//}

static int
reenable_vcs(SslEntry *entry, SSL_CTX *ctx)
{
  while (entry->waitingVConns.begin() != entry->waitingVConns.end()) {
    // Associating the ctx with the ssl vc, and then re-enabling the vc to
    // continue processing the requestt
    TSVConn vc = entry->waitingVConns.front();
    entry->waitingVConns.pop_front();
    TSDebug("ssl-lazy-loader-backlog",
            "POPped the vc %p for %p for %s off the "
            "waitingVConns",
            vc, entry, entry->redis_CN.c_str());

    TSDebug("redis-loader-thread", "Getting the SSL Connection for %s", entry->request_domain.c_str());
    TSSslConnection sslobj = TSVConnSSLConnectionGet(vc);
    SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
    SSL_set_SSL_CTX(ssl, ctx);
    TSDebug("redis-loader-thread", "Resolving the SSL ctx for %s using ", entry->redis_CN.c_str());
    TSVConnReenable(vc);
  }
  return TS_SUCCESS;
}

static int
shutdown_vcs(SslEntry *entry, SSL_CTX *ctx)
{
  while (entry->waitingVConns.begin() != entry->waitingVConns.end()) {
    TSVConn vc = entry->waitingVConns.front();
    entry->waitingVConns.pop_front();
    TSDebug("ssl-lazy-loader-backlog",
            "POPped the vc %p for %p for %s off the "
            "waitingVConns",
            vc, entry, entry->redis_CN.c_str());

    TSDebug("redis-loader-thread", "Closing down the SSL connection for %s", entry->redis_CN.c_str());
    // TSVConnClose(vc);
    TSVConnReenable(vc);
  }
  return TS_SUCCESS;
}

int
Loader_Cont(SslEntry *entry)
{
  TSDebug("redis-loader-thread", "Resolving the SSL ctx for %s in the Loader Thread", entry->request_domain.c_str());

  // Make sure we have some sort of common name to search for
  redisReply *r_reply = NULL;
  if (entry->redis_CN.length() > 0) {
    TSDebug("redis-loader-thread",
            "redis_CN is already set to %s "
            "in the Loader_Cont",
            entry->request_domain.c_str());
  } else if (entry->request_domain.length() > 0) {
    TSDebug("redis-loader-thread",
            "Setting redis_CN to %s using "
            "the the (request_domain.length > 0) in the Loader_Cont",
            entry->request_domain.c_str());
    entry->redis_CN = entry->request_domain;
  } else {
    TSDebug("redis-loader-thread", "Both redis_CN and request_domain"
                                   "are zero length. This SHOULD NEVER HAPPEN!!!");
    return TS_ERROR;
  }

  // lets check to make sure this domain
  // exists in redis to make sure we should even try to load this guy's cert
  //
  // Let's GET the value (Common Name) for this domain (which also
  // validates the domain)
  std::string s_servername = entry->request_domain;
  TSDebug("redis-loader-thread", "before domain_map->get, thread_loader_data.nd_domain_map =  %p ",
          thread_loader_data.nd_domain_map);
  if (thread_loader_data.nd_domain_map->get(r_reply, dom_c_name, entry->request_domain.c_str()) != REDIS_REPLY_ERROR) {
    TSDebug("redis-loader-thread", "after domain_map->get, thread_loader_data.nd_domain_map =  %p ",
            thread_loader_data.nd_domain_map);
    if (r_reply->type == REDIS_REPLY_NIL) { // domain.com not found, check for wildcard CN
      size_t dot_cnt = std::count(s_servername.begin(), s_servername.end(), '.');
      if (dot_cnt > 1) { // sub.domain.com
        // we have a domain with a subdomain but we didn't find the
        // original requested domain in redis.  Let's make this into a
        // wildcard and see if it matches
        std::size_t found    = s_servername.find('.');
        char *p_s_servername = &(s_servername[found]);
        if (found != std::string::npos && found > 0) {
          TSDebug("redis-connector", "first 'dot' found at: %lu", found);
          TSDebug("redis-connector", "servername[found]: %s", p_s_servername);
          p_s_servername--;
          *p_s_servername = '*'; // inject a '*' to make it a wildcard
          TSDebug("redis-connector", "derived wildcard: %s", p_s_servername);
          if (thread_loader_data.nd_domain_map->get(r_reply, dom_c_name, p_s_servername) != REDIS_REPLY_ERROR) {
            if (r_reply->type == REDIS_REPLY_NIL) { // not found, check for wildcard CN
              TSStatIntIncrement(statistics.domain_lookup_failed, 1);

              shutdown_vcs(entry, NULL);
              // reenable_vcs(entry, NULL);
              TSDebug("redis-connector", "%s was not found in redis", p_s_servername);
              if (r_reply)
                freeReplyObject(r_reply);
              return TS_ERROR;
            }
          } else { // domain_map->get() for a wildcard return a NIL - not found
            TSStatIntIncrement(statistics.domain_lookup_failed, 1);
            // reenable_vcs(entry, NULL);
            shutdown_vcs(entry, NULL);
            TSDebug("redis-connector", "GET domain_name and wildcard domain_name "
                                       "ERRORED. We're done here");
            if (r_reply)
              freeReplyObject(r_reply);
            return TS_ERROR;
          }
        }
      } else { // not sub.domain.com, so no need to do a wildcard lookup
        TSStatIntIncrement(statistics.domain_lookup_failed, 1);
        // reenable_vcs(entry, NULL);
        shutdown_vcs(entry, NULL);
        TSDebug("redis-connector", "GET domain_name  "
                                   "returned a NIL - not found. We're done here");
        if (r_reply)
          freeReplyObject(r_reply);
        return TS_ERROR;
      }
    } else if (r_reply->type == REDIS_REPLY_STRING) { // domain_map->get() for domain.com returned a string value
      if (strlen(r_reply->str) > 0) {
        entry->redis_CN = r_reply->str;
      } else {
        TSStatIntIncrement(statistics.domain_lookup_failed, 1);
        shutdown_vcs(entry, NULL);
        // reenable_vcs(entry, NULL);
        if (r_reply)
          freeReplyObject(r_reply);
        return TS_ERROR;
      }
    } else { // Unknown r_reply->type  - not NIL or STRING
      TSStatIntIncrement(statistics.domain_lookup_failed, 1);
      reenable_vcs(entry, NULL);
      TSDebug("redis-connector", "GET domain_name and wildcard domain_name "
                                 "FAILED with an unknown reply type. We're done here");
      if (r_reply)
        freeReplyObject(r_reply);
      return TS_ERROR;
    }
  } else { // redis GET returned a REDIS_REPLY_ERROR
    TSStatIntIncrement(statistics.domain_lookup_failed, 1);
    // reenable_vcs(entry, NULL);
    shutdown_vcs(entry, NULL);
    TSDebug("redis-connector", "GET domain_name "
                               "ERRORED. We're done here");
    if (r_reply)
      freeReplyObject(r_reply);
    return TS_ERROR;
  }

  std::string request_cert;
  if (thread_loader_data.nd_cert_map->get(r_reply, crt_c_name, entry->redis_CN.c_str()) != REDIS_REPLY_ERROR) {
    if (r_reply != NULL && r_reply->type == REDIS_REPLY_STRING) {
      request_cert = r_reply->str;
    } else if (r_reply != NULL && r_reply->type == REDIS_REPLY_ERROR) {
      TSStatIntIncrement(statistics.cert_lookup_failed, 1);
      // reenable_vcs(entry, NULL);
      shutdown_vcs(entry, NULL);
      TSDebug("redis-connector",
              "GET cert failed "
              "- redis return the error %s",
              r_reply->str);
      if (r_reply)
        freeReplyObject(r_reply);
      return TS_ERROR;
    } else {
      TSStatIntIncrement(statistics.cert_lookup_failed, 1);
      shutdown_vcs(entry, NULL);
      // reenable_vcs(entry, NULL);
      TSDebug("redis-connector",
              "GET cert failed. We're done here "
              "- r_reply->type = %d:%s",
              r_reply->type, r_reply->str);
      if (r_reply)
        freeReplyObject(r_reply);
      return TS_ERROR;
    }
  } else {
    TSStatIntIncrement(statistics.cert_lookup_failed, 1);
    // reenable_vcs(entry, NULL);
    shutdown_vcs(entry, NULL);
    TSDebug("redis-connector", "GET cert  "
                               "ERRORED. We're done here");
    if (r_reply)
      freeReplyObject(r_reply);
    return TS_ERROR;
  }

  TSDebug(PN, "Loading the cert from inside the Loader_Cont");
  if (entry && entry->ctx == NULL) {
    // Must process the certificate data
    std::deque<std::string> cert_names;
    entry->ctx = Load_Certificate_From_Memory(entry, cert_names, request_cert);

    // Bump the stat counter
    TSStatIntIncrement(statistics.certs_loaded_current, 1);
    TSStatIntIncrement(statistics.certs_loaded_total, 1);
  }

  TSDebug("ssl-lazy-loader-backlog",
          "Size of the waitingVConns deque %lu at "
          "resolving the SSL ctx %s cert from inside the "
          "Loader_Cont, re-enabling all VCs waiting on this cert",
          entry->waitingVConns.size(), entry->redis_CN.c_str());

  reenable_vcs(entry, entry->ctx);
  if (r_reply)
    freeReplyObject(r_reply);

  return TS_SUCCESS;
}

void
dataset_check(void)
{
  // Let's see if we have a dataset already created for this continuation
  // TSCont loader_cont;

  // if (!thread_req_data.thread_initialized || !thread_loader_data.thread_initialized) {
  if (!thread_loader_data.thread_initialized) {
    TSDebug("ssl-lazy-loader-backlog", "Initializing thread data.");

    redisReply *r_reply = NULL;
    //    thread_loader_data.sd_cert_map = new RedisConnector(crt_c_name, Sentinels);
    //    if (thread_loader_data.sd_cert_map->auth(r_reply, crt_c_name) == REDIS_OK){
    //      TSDebug("ssl-lazy-loader-backlog", "Redis %s authenticated successfully!", crt_c_name.c_str());
    //    }
    //
    //    thread_loader_data.sd_domain_map = new RedisConnector(dom_c_name, Sentinels);
    //    if (thread_loader_data.sd_domain_map->auth(r_reply, dom_c_name) == REDIS_OK){
    //        TSDebug("ssl-lazy-loader-backlog", "Redis %s authenticated successfully!", dom_c_name.c_str());
    //    }

    thread_loader_data.nd_cert_map = new RedisConnector(crt_c_name, ndSentinels);
    if (thread_loader_data.nd_cert_map->auth(r_reply, crt_c_name) == REDIS_OK) {
      TSDebug("ssl-lazy-loader-backlog", "Redis %s authenticated successfully!", crt_c_name.c_str());
    }

    thread_loader_data.nd_domain_map = new RedisConnector(dom_c_name, ndSentinels);
    if (thread_loader_data.nd_domain_map->auth(r_reply, dom_c_name) == REDIS_OK) {
      TSDebug("ssl-lazy-loader-backlog", "Redis %s authenticated successfully!", dom_c_name.c_str());
    }

    if (r_reply)
      freeReplyObject(r_reply);

    thread_loader_data.entry              = NULL;
    thread_loader_data.thread_initialized = 1;

    // thread_req_data.loader_cont = loader_cont;

    // thread_req_data.thread_initialized = 1;
  }
  return;
}

int
CB_Life_Cycle(TSCont, TSEvent, void *)
{
  // By now the SSL library should have been initialized,
  // We can safely parse the config file and load the ctx tables
  //  TSDebug(PN, "Starting Load SSL Configuration");
  //  Load_Configuration();
  //  TSDebug(PN, "SSL Load_Configuration Complete");

  TSDebug(PN, "Starting Load Redis Configuration");
  if (Load_Redis_Configuration() < 0) {
    TSError(PCP "Failed to load the redis config file, check debug output for errata");
  }
  TSDebug(PN, "Redis Sentinels Load Configuration Complete");

  //  ink_hrtime expiry_thread_sched_ms = RedisEvictFrequency * 60 * 1000;
  //  expiry_cont = TSContCreate(Expiry_Thread, TSMutexCreate());
  //  TSDebug(PN, "Scheduling cert expiry background thread for every %d minutes "
  //          "with a Cert TTL time of %d minutes",
  //          RedisEvictFrequency, RedisCertTTL);
  //  TSContSchedule(expiry_cont, expiry_thread_sched_ms, TS_THREAD_POOL_TASK);

  TSDebug(PN, "Plugin online");
  return TS_SUCCESS;
}

int
CB_servername(TSCont cont, TSEvent /*event*/, void *edata)
{
  TSVConn ssl_vc         = reinterpret_cast<TSVConn>(edata);
  TSSslConnection sslobj = TSVConnSSLConnectionGet(ssl_vc);
  SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
  const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  TSDebug(PN, "SNI callback servername %s ssl_vc %p", servername, ssl_vc);
  if (servername != NULL) {
    dataset_check();

    SslEntry *entry     = NULL;
    entry               = new SslEntry();
    entry->certFileName = "";
    entry->keyFileName  = "";
    entry->ctx          = NULL;
    entry->op           = SSL_HOOK_OP_DEFAULT;
    entry->set_load_time(time(0));
    entry->set_access_time(time(0));
    entry->request_domain = servername;
    entry->mutex          = TSMutexCreate();
    TSDebug("ssl-lazy-loader-backlog",
            "PUSHing the vc %p for %p for %s onto the "
            "waitingVConns while creating the new entry in CB_servername",
            ssl_vc, entry, servername);
    entry->waitingVConns.push_back(ssl_vc);
    TSDebug("ssl-lazy-loader-backlog",
            "Size of the waitingVConns deque %lu at "
            "creating the new entry for the %s cert "
            "after pushing into the que",
            entry->waitingVConns.size(), servername);

    Loader_Cont(entry);
    return TS_SUCCESS; // don't re-enable yet
  }
  // All done, reactivate things
  TSVConnReenable(ssl_vc);
  return TS_SUCCESS;
}

} // namespace

// Called by ATS as our initialization point
void
TSPluginInit(int argc, const char *argv[])
{
  bool success = false;

  TSPluginRegistrationInfo info;
  info.plugin_name   = (char *)("ssl-lay-loader");
  info.vendor_name   = (char *)("GoDaddy");
  info.support_email = (char *)("sfeltner@godaddy.com");

  TSCont cb_lc                         = 0; // life cycle callback continuuation
  TSCont cb_sni                        = 0; // SNI callback continuuation
  static const struct option longopt[] = {{const_cast<char *>("config"), required_argument, NULL, 'c'},
                                          {const_cast<char *>("redis"), required_argument, NULL, 'r'},
                                          {NULL, no_argument, NULL, '\0'}};

  int opt = 0;
  while (opt >= 0) {
    opt = getopt_long(argc, (char *const *)argv, "c:r:", longopt, NULL);
    switch (opt) {
    case 'c': // no longer used
      ConfigPath = optarg;
      ConfigPath = std::string(TSConfigDirGet()) + '/' + std::string(optarg);
      break;
    case 'r':
      RedisConfigPath = optarg;
      RedisConfigPath = std::string(TSConfigDirGet()) + '/' + std::string(optarg);
      break;
    }
  }
  if (RedisConfigPath.length() == 0) {
    static char const *const DEFAULT_REDIS_CONFIG_PATH = "ssl_redis.cfg";
    RedisConfigPath = std::string(TSConfigDirGet()) + '/' + std::string(DEFAULT_REDIS_CONFIG_PATH);
    TSDebug(PN, "No config path set in arguments, using default: %s", DEFAULT_REDIS_CONFIG_PATH);
  }

  // #if (TS_VERSION_NUMBER >= 7000000)
  if (TS_SUCCESS != TSPluginRegister(&info)) { // This is for 6.x
    TSError(PCP "registration failed.");
    //  }
    //#else
    //  if (TS_SUCCESS != TSPluginRegister(TS_SDK_VERSION_3_0, &info)) { // 5.3
    //    TSError(PCP "registration failed.");
    //  }
    //#endif
  } else if (TSTrafficServerVersionGetMajor() < 5) {
    TSError(PCP "requires Traffic Server 5.0 or later.");
  } else if (0 == (cb_lc = TSContCreate(&CB_Life_Cycle, TSMutexCreate()))) {
    TSError(PCP "Failed to lifecycle callback.");
  } else if (0 == (cb_sni = TSContCreate(&CB_servername, TSMutexCreate()))) {
    TSError(PCP "Failed to create SNI callback.");
  } else {
    TSLifecycleHookAdd(TS_LIFECYCLE_PORTS_INITIALIZED_HOOK, cb_lc);
    TSHttpHookAdd(TS_SSL_SNI_HOOK, cb_sni);
    success = true;
  }

  if (StatsInit() == TS_ERROR) {
    TSError(PCP "Stat creation failed. Can't create counter: ");
  }

  if (!success) {
    if (cb_lc)
      TSContDestroy(cb_lc);
    TSError(PCP "not initialized");
  }
  TSDebug(PN, "Plugin init %s", success ? "successful" : "failed");

  return;
}
