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
#include "I_Machine.h"
#include "../IPAllow.h"

ProxyProtocolSessionAccept::ProxyProtocolSessionAccept(const HttpSessionAccept::Options &_o) : SessionAccept(nullptr), options(_o)
{
  SET_HANDLER(&ProxyProtocolSessionAccept::mainEvent);
}

ProxyProtocolSessionAccept::~ProxyProtocolSessionAccept()
{
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

  if (proxyprotocol_drain) {
    return false;
  }

  netvc->attributes = this->options.transport_type;

  if (is_debug_tag_set("proxyprotocol_seq")) {
    ip_port_text_buffer ipb;

    Debug("proxyprotocol_seq", "[ProxyProtocolSessionAccept:mainEvent %p] accepted connection from %s transport type = %d", netvc,
          ats_ip_nptop(client_ip, ipb, sizeof(ipb)), netvc->attributes);
  }

  ProxyProtocolClientSession *new_session = THREAD_ALLOC_INIT(proxyprotocolClientSessionAllocator, this_ethread());
  new_session->acl_record         = session_acl_record;
  new_session->new_connection(netvc, iobuf, reader, false /* backdoor */);

  return true;
}

int
ProxyProtocolSessionAccept::mainEvent(int event, void *data)
{
  NetVConnection *netvc;
  ink_release_assert(event == NET_EVENT_ACCEPT || event == EVENT_ERROR);
  ink_release_assert((event == NET_EVENT_ACCEPT) ? (data != nullptr) : (1));

  if (event == NET_EVENT_ACCEPT) {
    netvc = static_cast<NetVConnection *>(data);
    if (!this->accept(netvc, nullptr, nullptr)) {
      netvc->do_io_close();
    }
    return EVENT_CONT;
  }

  // XXX We should hoist the error handling so that all the protocols generate the statistics
  // without code duplication.
  if (((long)data) == -ECONNABORTED) {
    HTTP_SUM_DYN_STAT(http_ua_msecs_counts_errors_pre_accept_hangups_stat, 0);
  }

  ink_abort("ProxyProtocol accept received fatal error: errno = %d", -((int)(intptr_t)data));
  return EVENT_CONT;
}
