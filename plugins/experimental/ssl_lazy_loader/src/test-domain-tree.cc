#include <stdio.h>
#include <memory.h>
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <string>
#include <deque>
#include <ts/ts.h>
#include <tsconfig/TsValue.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "domain-tree.h"

#include "ts/ink_inet.h"
#include "ts/ink_config.h"
// #include "ts/ink_time.h"
#include "tscore/ink_hrtime.h"
#include "ts/IpMap.h"

class CertLookup
{
public:
  DomainNameTree tree;
  /// IpMap ipmap;
} Lookup;

class SslEntry
{
public:
  SslEntry() : ctx(NULL), op(TS_SSL_HOOK_OP_DEFAULT)
  {
    // this->mutex = TSMutexCreate();
  }

  ~SslEntry() {}

  SSL_CTX *ctx;
  TSSslVConnOp op;
  // If the CTX is not already created, use these
  // files to load things up
  std::string certFileName;
  std::string keyFileName;
  std::string request_domain;
  // TSMutex mutex;
  std::deque<TSVConn> waitingVConns;
  ink_time_t load_time;
  ink_time_t access_time;
  // Common Name fetched from redis
  std::string redis_CN;

  void
  set_load_time(ink_time_t this_time)
  {
    load_time = this_time;
  }

  void
  set_access_time(ink_time_t this_time)
  {
    access_time = this_time;
  }
};

int
main(int argc, char **argv)
{
  int num_nodes = 9;
  std::string servername;
  DomainNameTree::DomainNameNode *node;
  int Parse_order = 0;

  if (argc < 2)
    return EXIT_FAILURE;

  // load set with first file
  std::ifstream inf(argv[1]);
  std::deque<std::string> lines;
  for (unsigned int i = 1; std::getline(inf, servername); ++i) {
    if (servername.find("#") == 0) {
      continue;
    }
    lines.push_back(servername);
  }

  for (int i = 0; i < lines.size(); ++i) {
    servername = lines.at(i);
    std::cout << ' ' << servername << std::endl;

    // now let's create a node entry for this guy and then insert it into
    // the domain lookup tree so we don't have to do it again.
    SslEntry *entry     = NULL;
    entry               = new SslEntry();
    entry->certFileName = "";
    entry->keyFileName  = "";
    entry->ctx          = NULL;
    entry->op           = TS_SSL_HOOK_OP_DEFAULT;
    entry->set_load_time(time(0));
    entry->set_access_time(time(0));
    entry->redis_CN = servername;
    Lookup.tree.insert(servername, entry, Parse_order++);
    node = Lookup.tree.findFirstMatch(servername);
  }

  srand(time(0));
  int rand_el = rand() % (int)(lines.size());
  std::cout << "Random domain: " << rand_el << " " << lines.at(rand_el) << std::endl;
  node                  = Lookup.tree.findFirstMatch(lines.at(rand_el));
  SslEntry *found_entry = reinterpret_cast<SslEntry *>(node->payload);
  std::cout << "Found a node with this servername: " << found_entry->redis_CN << std::endl << std::endl;

  std::cout << "dump() returned a count of: " << Lookup.tree.dump() << std::endl << std::endl;

  rand_el = rand() % (int)(lines.size());
  std::cout << "Random domain: " << rand_el << " " << lines.at(rand_el) << std::endl;
  node        = Lookup.tree.findFirstMatch(lines.at(rand_el));
  found_entry = reinterpret_cast<SslEntry *>(node->payload);
  std::cout << "Removing this servername: " << found_entry->redis_CN << std::endl << std::endl;
  Lookup.tree.remove(found_entry->redis_CN);

  std::cout << "dump() returned a count of: " << Lookup.tree.dump() << std::endl;

  return 0;
}
