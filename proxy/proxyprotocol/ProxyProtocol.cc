/** @file
 *
 *  Fundamental HTTP/2 protocol definitions and parsers.
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "ts/ink_assert.h"
#include "ProxyProtocol.h"


bool
proxy_protov1_parse(NetVConnection *netvc, char *buf)
{
  std::string src_addr_port;
  std::string dst_addr_port;

  char *pch;
  int cnt = 0;
  pch = strtok (buf," \n\r");
  while (pch!= NULL) {
    switch (cnt) {
      case 0:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = PREFACE",cnt, pch);
        break;
      // After the PROXY, exactly one space followed by the INET protocol family
      // - TCP4, TCP6 or UNKNOWN
      case 1:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = INET Protocol",cnt, pch);
        break;
      // Next up is exactly one space and the layer 3 source address
      // - 255.255.255.255 or ffff:f...f:ffff ffff:f...f:fff
      case 2:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = Source Address",cnt, pch);
        //netvc->set_proxy_protocol_src_addr(addr_port);
        src_addr_port.assign(pch);
        break;
      // Next is exactly one space followed by the layer3 destination address
      // - 255.255.255.255 or ffff:f...f:ffff ffff:f...f:fff
      case 3:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = Destination Address",cnt, pch);
        dst_addr_port.assign(pch);
        break;
      // Next is exactly one space followed by TCP source port represented as a
      //   decimal number in the range of [0..65535] inclusive.
      case 4:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = Source Port",cnt, pch);
        src_addr_port = src_addr_port + ":" + pch;
        netvc->set_proxy_protocol_src_addr(ts::string_view(src_addr_port));
        //netvc->set_proxy_protocol_src_port(1);
        break;
      // Next is exactly one space followed by TCP destination port represented as a
      //   decimal number in the range of [0..65535] inclusive.
      case 5:
        Debug("proxyprotocol_v1", "proto_has_proxy_v1: token[%d]:[%s] = Destination Port",cnt, pch);
        dst_addr_port = dst_addr_port + ":" + pch;
        netvc->set_proxy_protocol_dst_addr(ts::string_view(dst_addr_port));
        //netvc->set_proxy_protocol_dst_port(2);

        // THIS RIGHT HERE!  Fill in these fields into the netvc and then pull the 
        // data back out in the add_forwarded header function!
        // Oh, and do this in the SSL stuff also!

        break;
    }
    // if we have our all of our fields, set version as a flag, we are done here
    //  otherwise increment our field counter and tok another field
    if (cnt >= 6) {
      netvc->set_proxy_protocol_version(NetVConnection::PROXY_V1);
      break;
    } else {
      ++cnt;
      pch = strtok (NULL, " \n\r");
    }
  }

  // Can I then stash this data away somewhere in the structure so it can be
  // retrieved before it gets sent down the stack?

  // Make sure we get the required number of fields
  return (cnt == 6 ? true : false);
}
