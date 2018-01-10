/** @file

  A brief file description

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

#include "ProxyProtocolSessionAccept.h"
#include "ProxyProtocolClientSession.h"
#include "P_SSLNetVConnection.h"
#include "P_SSLNextProtocolAccept.h"
#include "I_Machine.h"
#include "../IPAllow.h"

//ProxyProtocolSessionAccept::ProxyProtocolSessionAccept(Continuation *ep, bool transparent_passthrough)
//  : SessionAccept(nullptr), buffer(new_empty_MIOBuffer()), endpoint(ep), transparent_passthrough(transparent_passthrough)
//ProxyProtocolSessionAccept::ProxyProtocolSessionAccept(Continuation *ep, bool transparent_passthrough)
//  : SSLNextProtocolAccept(ep, transparent_passthrough), buffer(new_empty_MIOBuffer()), endpoint(ep), 
//    transparent_passthrough(transparent_passthrough)
//    
//{
//  SET_HANDLER(&ProxyProtocolSessionAccept::mainEvent);
//}

//ProxyProtocolSessionAccept::ProxyProtocolSessionAccept(const HttpSessionAccept::Options &_o) : SessionAccept(nullptr), options(_o)
//{
//  SET_HANDLER(&ProxyProtocolSessionAccept::mainEvent);
//}

ProxyProtocolSessionAccept::~ProxyProtocolSessionAccept()
{
  //free_MIOBuffer(this->buffer);
}

bool
ProxyProtocolSessionAccept::accept(NetVConnection *netvc, MIOBuffer *iobuf, IOBufferReader *reader)
{
  sockaddr const *client_ip           = netvc->get_remote_addr();
  const AclRecord *session_acl_record = testIpAllowPolicy(client_ip);
  if (!session_acl_record) {
    ip_port_text_buffer ipb;
    Warning("ProxyProtocol client '%s' prohibited by ip-allow policy", ats_ip_ntop(client_ip, ipb, sizeof(ipb)));
    return false;
  }

  char buf[PROXY_V1_CONNECTION_PREFACE_LEN];
  char *end;
  ptrdiff_t nbytes;

  end    = reader->memcpy(buf, sizeof(buf), 0 /* offset */);
  nbytes = end - buf;

  // Client must send at least 4 bytes to get a reasonable match.
  if (nbytes < MIN_V1_HDR_LEN) {
    return false;
  }

  if (memcmp(PROXY_V1_CONNECTION_PREFACE, buf, PROXY_V1_CONNECTION_PREFACE_LEN_MIN) != 0) {
    return false;
  }

  int64_t ret;
  ret = reader->memchr('\r', strlen(buf), 0);
  ret = reader->memchr('\n', strlen(buf), 0);

  char local_buf[256];   // <- there is a max - LOOK IT UP!
  reader->read(local_buf, ret+1);

  // Now that we know we have a valid PROXY V1 preface, let's parse the
  // remainder of the header

  std::string src_addr_port;
  std::string dst_addr_port;

  char *pch;
  int cnt = 0;
  pch = strtok (local_buf," \n\r");
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
//}
//  netvc->attributes = this->options.transport_type;
//
//  if (is_debug_tag_set("proxyprotocol_seq")) {
//    ip_port_text_buffer ipb;
//    Debug("proxyprotocol_seq", "[ProxyProtocolSessionAccept:mainEvent %p] accepted connection from %s transport type = %d", netvc,
//          ats_ip_nptop(client_ip, ipb, sizeof(ipb)), netvc->attributes);
//  }
//
////  ProxyProtocolClientSession *new_session = THREAD_ALLOC_INIT(proxyprotocolClientSessionAllocator, this_ethread());
//  ProxyProtocolClientSession *new_session = ProxyProtocolClientSession::alloc();
//  new_session->acl_record         = session_acl_record;
//  new_session->new_connection(netvc, iobuf, reader, false /* backdoor */);
//
//  return true;
}

int
ProxyProtocolSessionAccept::mainEvent(int event, void *edata)
{
  //NetVConnection *netvc;
  //netvc = static_cast<NetVConnection *>(edata);

  SSLNetVConnection *netvc = ssl_netvc_cast(event, edata);
  Debug("proxyprotocol", "[ProxyProtocolSessionAccept:mainEvent] event %d netvc %p", event, netvc);
  if (event == NET_EVENT_ACCEPT) {
    ink_release_assert(netvc != nullptr);

    // Register our protocol set with the VC and kick off a zero-length read to
    // force the SSLNetVConnection to complete the SSL handshake. Don't tell
    // the endpoint that there is an accept to handle until the read completes
    // and we know which protocol was negotiated.
    netvc->registerNextProtocolSet(this->protoset);
    netvc->do_io_read(new SSLNextProtocolTrampoline(this, netvc->mutex), 0, this->buffer);
    if (!this->accept(netvc, this->buffer, reader)) {
      netvc->do_io_close();
      return EVENT_DONE;
    }
    return EVENT_CONT;
  }

  netvc->do_io_close();
  return EVENT_CONT;
  // ink_release_assert(event == NET_EVENT_ACCEPT || event == EVENT_ERROR);
  // ink_release_assert((event == NET_EVENT_ACCEPT) ? (data != nullptr) : (1));

  // if (event == NET_EVENT_ACCEPT) {
  //   netvc = static_cast<NetVConnection *>(data);
  //   if (!this->accept(netvc, nullptr, nullptr)) {
  //     netvc->do_io_close();
  //   }
  //   return EVENT_CONT;
  // }

  // ink_abort("ProxyProtocol accept received fatal error: errno = %d", -((int)(intptr_t)data));
  // return EVENT_CONT;
}

//void
//ProxyProtocolSessionAccept::registerEndpoint(SessionAccept *ap)
//{
//  //ink_release_assert(endpoint[key] == nullptr);
//  this->endpoint = ap;
//}

bool
ProxyProtocolSessionAccept::registerEndpoint(const char *protocol, Continuation *handler)
{
  this->endpoint = handler;
  //return this->protoset->registerEndpoint(protocol, handler);
  return true;
}

//bool
//ProxyProtocolSessionAccept::unregisterEndpoint(const char *protocol, Continuation *handler)
//{
//  return this->protoset.unregisterEndpoint(protocol, handler);
//}

