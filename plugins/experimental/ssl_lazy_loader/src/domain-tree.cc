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
#include "domain-tree.h"
#include "sslentry.h"
#include "stats.h"
#include <iostream>
#include <fstream>
#include <string>
#include <typeinfo>
#include <algorithm>

// return true if comparable.  Return type of compare in relative parameter
// 0 if eq.  < 0 if node key is broader.  > 0 if parameter key is broader
bool
DomainNameTree::DomainNameNode::compare(std::string key, int &relative)
{
  size_t star_loc = key.find("*");
  bool is_wild    = false;

  if (star_loc != std::string::npos) {
    star_loc++;
    is_wild = true;
    key     = key.substr(star_loc);
  }
  return this->prunedCompare(key, relative, is_wild);
}

bool
DomainNameTree::DomainNameNode::prunedCompare(std::string key, int &relative, bool is_wild)
{
  if (key == this->key) {
    relative = 0;
    return true;
  } else {
    size_t loc = key.find(this->key);
    if (loc != std::string::npos) {
      if ((key.length() - this->key.length()) == loc) {
        // And node key is at the end of search key
        relative = 1;
        return true;
      }
    }
    if (this->is_wild) {
      size_t loc = key.find(this->key);

      if (this->key == "") { // Match all
        relative = -1;
        return true;
      } else if (loc != std::string::npos) {
        // node key is in search key
        if ((key.length() - this->key.length()) == loc) {
          // And node key is at the end of search key
          relative = -1;
          return true;
        }
      }
    }
    if (is_wild) {
      if (key == "") { // Match all
        relative = 1;
        return true;
      } else {
        size_t loc = this->key.find(key);

        if (loc != std::string::npos) {
          if ((this->key.length() - key.length()) == loc) {
            relative = 1;
            return true;
          }
        }
      }
    }
  }
  return false;
}

DomainNameTree::DomainNameNode *
DomainNameTree::find(std::string key, bool best_match)
{
  DomainNameNode *retval = NULL;
  DomainNameNode *first  = NULL;
  size_t star_loc        = key.find("*");
  bool is_wild           = false;

  if (star_loc != std::string::npos) {
    key     = key.substr(star_loc + 1);
    is_wild = true;
  }

  bool set_iter                = false;
  DomainNameNode *current_node = root;
  std::deque<DomainNameNode *>::iterator sibPtr, endPtr;

  while (current_node != NULL) {
    bool partial_match = false;
    int relative;

    if (current_node->prunedCompare(key, relative, is_wild)) {
      if (relative == 0) {
        retval = current_node;
        if (NULL == first || retval->order < first->order) {
          first = retval;
        }
        current_node = NULL;
        break;
      } else if (relative < 0) {
        retval        = current_node;
        partial_match = true;
        if (NULL == first || retval->order < first->order) {
          first = retval;
        }
      }
    }

    /// need to update the retval to the last current_node somewhere in here!!!!!
    /// the problem here is that pruned Compare returns false for www.domain.com
    /// compared with domain.com

    if (partial_match) {
      // Check out the children, maybe there is something better there
      sibPtr   = current_node->children.begin();
      endPtr   = current_node->children.end();
      set_iter = true;
      if (sibPtr == endPtr) {
        break; // We are done
      }
      current_node = *(sibPtr++);
    } else { // No match here.  Look at next sibling?
      // Is there another sibling to look at?
      if (set_iter && sibPtr != endPtr) {
        current_node = *(sibPtr++);
      } else { // No more siblings to check, give it up.
        break;
      }
    }
  }

  return best_match ? retval : first;
}

DomainNameTree::DomainNameNode *
DomainNameTree::insert(std::string key, void *payload, int order)
{
  TSMutexLock(this->tree_mutex);
  DomainNameNode *retval = NULL;
  DomainNameNode *node   = this->findBestMatch(key);
  int relative;

  if (node->compare(key, relative)) {
    size_t star_loc = key.find("*");
    bool is_wild    = false;

    if (star_loc != std::string::npos) {
      star_loc++;
      key     = key.substr(star_loc);
      is_wild = true;
    }
    if (relative < 0) {
      // Make a new node that is a child of node
      DomainNameNode *new_node = new DomainNameNode(key, payload, order, is_wild, time(0));

      new_node->parent = node;
      node->children.push_back(new_node);
      retval = new_node;
    } else if (relative > 0) {
      // Insert new node as parent of node
      DomainNameNode *new_node = new DomainNameNode(key, payload, order, is_wild, time(0));

      new_node->parent = node->parent;
      new_node->children.push_back(node);

      // Replace the node with new_node in the child list of the parent;
      for (std::deque<DomainNameNode *>::iterator iter = node->parent->children.begin(); iter != node->parent->children.end();
           ++iter) {
        if (*(iter) == node) {
          *(iter) = new_node;
        }
      }
      retval = new_node;
    } else {
      // Will not replace in the equal case
      // Unless this is the root node
      if (node->key == "" && node->order == 0x7fffffff) {
        node->key     = key;
        node->payload = payload;
        node->order   = order;
        retval        = node;
      }
    }
  }
  //*  if (retval != NULL) {
  //*TSDebug("ssl-domain-tree", "Just inserted: %s",  retval->key.c_str());
  //*  } else {
  //*TSDebug("ssl-domain-tree", "Skipped the insert since it was already inserted");
  //*  }

  // dump();
  TSMutexUnlock(this->tree_mutex);

  return retval;
}

DomainNameTree::DomainNameNode *
DomainNameTree::remove(std::string key)
{
  TSMutexLock(this->tree_mutex);
  static DomainNameNode *node = NULL;
  DomainNameNode *retval      = NULL;
  node                        = this->findBestMatch(key);
  retval                      = node;
  int relative;

  // dump();
  if (node->compare(key, relative)) {
    size_t star_loc = key.find("*");

    if (star_loc != std::string::npos) {
      star_loc++;
      key = key.substr(star_loc);
    }

    // We found a match
    if (relative == 0) {
      TSDebug("ssl-domain-tree", "Node to be deleted: %s", node->key.c_str());
      SslEntry *node_entry = reinterpret_cast<SslEntry *>(node->payload);
      TSDebug("ssl-domain-tree", "  redis_CN [%s]", node_entry->redis_CN.c_str());
      std::deque<DomainNameNode *>::iterator endIter = node->children.end();
      for (std::deque<DomainNameNode *>::iterator iter = node->children.begin(); iter != endIter; iter++) {
        iter = node->children.erase(iter);
      }
      // ok, we erased the child entries from this entry's children deque
      // now, lets find ourselves in the root entry's deque
      TSDebug("ssl-domain-tree", "Node to be deleted: %s", node->key.c_str());
      endIter = node->parent->children.end();
      for (std::deque<DomainNameNode *>::iterator iter = node->parent->children.begin(); iter != endIter; iter++) {
        if ((*iter)->key == node->key) {
          iter = node->parent->children.erase(iter);
          break;
        }
      }
    }
  }
  TSMutexUnlock(this->tree_mutex);

  return retval;
}

int
DomainNameTree::expire(int evict_secs)
{
  TSMutexLock(this->tree_mutex);
  time_t delta_time;
  int count = 0;

  bool set_iter                = false;
  DomainNameNode *current_node = root;
  std::deque<DomainNameNode *>::iterator sibPtr, endPtr;

  while (current_node != NULL) {
    if (current_node->key != "") {
      char l_buf[256] = "NaN";
      ctime_r(&current_node->load_time, l_buf);
      delta_time = time(0) - current_node->load_time;
      if (delta_time > (evict_secs)) {
        TSDebug("ssl-lazy-expiry",
                "This %s cert has been in loaded for %ld seconds which "
                "exceeds the evict time of %d seconds. Evicting cert.",
                current_node->key.c_str(), delta_time, evict_secs);

        remove(current_node->key);
        count++;
        TSStatIntIncrement(statistics.certs_evicted_total, 1);
        TSStatIntDecrement(statistics.certs_loaded_current, 1);
      }
    }

    if (!set_iter) {
      sibPtr   = current_node->children.begin();
      endPtr   = current_node->children.end();
      set_iter = true;
    }
    if (sibPtr == endPtr) {
      break; // We are done
    }
    // Is there another sibling to look at?
    if (set_iter && sibPtr != endPtr) {
      current_node = *(sibPtr++);
    } else { // No more siblings to check, give it up.
      break;
    }
  }

  TSMutexUnlock(this->tree_mutex);

  return count;
}

int
DomainNameTree::dump(void)
{
  int count = 0;

  DomainNameNode *current_node = root;
  std::deque<DomainNameNode *>::iterator sibPtr, endPtr, l2sibPtr, l2endPtr;

  std::string indent = " ", l2indent = "  ";
  endPtr = current_node->children.end();

  for (sibPtr = current_node->children.begin(); sibPtr != endPtr; sibPtr++) {
    // std::cout << indent << (*sibPtr)->key << std::endl;
    l2endPtr = (*sibPtr)->children.end();
    for (l2sibPtr = (*sibPtr)->children.begin(); l2sibPtr != l2endPtr; l2sibPtr++) {
      // std::cout << l2indent << (*l2sibPtr)->key << std::endl;
    }
  }
  return count;
}
