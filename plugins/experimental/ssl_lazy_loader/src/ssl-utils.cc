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
#include <ts/ts.h>
#include <tsconfig/TsValue.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
// #include "ts/ink_inet.h"
// #include "ts/IpMap.h"
#include "ssl-utils.h"

void
Parse_Addr_String(ts::ConstBuffer const &text, IpRange &range)
{
  IpAddr newAddr;
  std::string textstr(text._ptr, text._size);
  // Is there a hyphen?
  size_t hyphen_pos = textstr.find("-");

  if (hyphen_pos != std::string::npos) {
    std::string addr1 = textstr.substr(0, hyphen_pos);
    std::string addr2 = textstr.substr(hyphen_pos + 1);
    range.first.load(ts::ConstBuffer(addr1.c_str(), addr1.length()));
    range.second.load(ts::ConstBuffer(addr2.c_str(), addr2.length()));
  } else { // Assume it is a single address
    newAddr.load(text);
    range.first  = newAddr;
    range.second = newAddr;
  }
}
