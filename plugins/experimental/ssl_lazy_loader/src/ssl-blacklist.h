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

#ifndef SSL_BLACKLIST_H
#define SSL_BLACKLIST_H

#include <string>
#include <cstring>
#include "ts/ts.h"
#include <tsconfig/TsValue.h>
#include "ts/ink_config.h"
#include "ts/ink_inet.h"
#include "ipaddr.h"
// #include <map>
#include <unordered_map>
#include <list>

namespace blacklist_lru
{
template <typename key_t, typename value_t> class BlacklistMap
{
public:
  typedef typename std::pair<key_t, value_t> key_value_pair_t;
  typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;

  BlacklistMap(size_t max_size) : _max_size(max_size) { mutex = TSMutexCreate(); }

  bool
  bl_isblacklisted(const key_t &name) const
  {
    return _cache_items_map.find(name) != _cache_items_map.end();

    //    bool ret_val = false;
    //    std::map<std::string, ink_hrtime>::iterator bl_it;
    //    if ((bl_it = hmap.find(name)) != hmap.end()) {
    //      ret_val = true;
    //    }
    //    return ret_val;
  }

  void
  bl_add(const key_t &name, const value_t &value)
  {
    TSDebug("ssl-lazy-loader-blacklist", "Blacklisting %s", name.c_str());
    TSMutexLock(mutex);
    auto it = _cache_items_map.find(name);
    _cache_items_list.push_front(key_value_pair_t(name, value));
    if (it != _cache_items_map.end()) {
      _cache_items_list.erase(it->second);
      _cache_items_map.erase(it);
    }
    _cache_items_map[name] = _cache_items_list.begin();

    if (_cache_items_map.size() > _max_size) {
      auto last = _cache_items_list.end();
      last--;
      TSDebug("ssl-lazy-loader-blacklist", "Removing %s from blacklist", last->first.c_str());
      _cache_items_map.erase(last->first);
      _cache_items_list.pop_back();
    }
    TSMutexUnlock(mutex);
  }

  const value_t &
  bl_get(const key_t &name)
  {
    auto it = _cache_items_map.find(name);
    if (it == _cache_items_map.end()) {
      TSDebug("ssl-lazy-loader-blacklist", "%s is not in the Blacklist", name.c_str());
    } else {
      _cache_items_list.splice(_cache_items_list.begin(), _cache_items_list, it->second);
      return it->second->second;
    }
  }

  //  bool
  //  bl_remove_check(std::string name) {
  //    bool ret_val = false;
  //    std::map<std::string, ink_hrtime>::iterator bl_it;
  //    if ((bl_it = hmap.find(name)) != hmap.end()) {
  //      if ((time(0) - bl_it->second) > (bl_timeout_mins * 60)) {
  //        TSDebug("ssl-lazy-loader-blacklist", "Domain %s has been on "
  //                "the blacklist long enough - removing",
  //                 bl_it->first.c_str());
  //        TSMutexLock(mutex);
  //        hmap.erase(name);
  //        TSMutexUnlock(mutex);
  //        ret_val = true;
  //      }
  //    }
  //    return ret_val;
  //  }

  size_t
  bl_set_maxsize(int size)
  {
    _max_size = size;
    return _max_size;
  }

  int
  bl_set_timeout(int timeout)
  {
    bl_timeout_mins = timeout;
    return bl_timeout_mins;
  }

  bool
  bl_clear_disabled(void)
  {
    bl_disabled = false;
    return bl_disabled;
  }

  bool
  bl_set_disabled(void)
  {
    bl_disabled = true;
    return bl_disabled;
  }

  bool
  bl_isdisabled(void)
  {
    return bl_disabled;
  }

private:
  //  std::map<std::string, ink_hrtime> hmap;
  int bl_timeout_mins = 0;
  bool bl_disabled    = false;
  TSMutex mutex;

  std::list<key_value_pair_t> _cache_items_list;
  std::unordered_map<key_t, list_iterator_t> _cache_items_map;
  size_t _max_size;
};

} // namespace blacklist_lru

#endif
