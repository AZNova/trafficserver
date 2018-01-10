/** @file

  ProtocolProbeSessionAccept

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

#include "P_Net.h"
#include "I_Machine.h"
#include "ProtocolProbeSessionAccept.h"
#include "http2/HTTP2.h"
#include "ProxyProtocol.h"

static bool
proto_is_http2(IOBufferReader *reader)
{
  char buf[HTTP2_CONNECTION_PREFACE_LEN];
  char *end;
  ptrdiff_t nbytes;

  end    = reader->memcpy(buf, sizeof(buf), 0 /* offset */);
  nbytes = end - buf;

  // Client must send at least 4 bytes to get a reasonable match.
  if (nbytes < 4) {
    return false;
  }

  ink_assert(nbytes <= (int64_t)HTTP2_CONNECTION_PREFACE_LEN);
  return memcmp(HTTP2_CONNECTION_PREFACE, buf, nbytes) == 0;
}

static bool
proto_has_proxy_v1(IOBufferReader *reader, NetVConnection *netvc)
{
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
}

static bool
proto_has_proxy_v2(IOBufferReader *reader)
{
  char buf[PROXY_V2_CONNECTION_PREFACE_LEN];
  char *end;
  ptrdiff_t nbytes;

  end    = reader->memcpy(buf, sizeof(buf), 0 /* offset */);
  nbytes = end - buf;

  // Client must send at least 4 bytes to get a reasonable match.
  if (nbytes < MIN_V2_HDR_LEN) {
    return false;
  }

  if (memcmp(PROXY_V2_CONNECTION_PREFACE, buf, PROXY_V2_CONNECTION_PREFACE_LEN_MIN) != 0) {
    return false;
  }

  int64_t ret;
  ret = reader->memchr('\r', strlen(buf), 0);
  Debug("proxyprotocol_v2", "proto_has_proxy_v2: reader->memchr(carriage_return) returned:%lld", ret);
  ret = reader->memchr('\n', strlen(buf), 0);
  Debug("proxyprotocol_v2", "proto_has_proxy_v2: reader->memchr(new_line) returned:%lld", ret);

  /**
    Copies and consumes data. Copies len bytes of data from the buffer
    into the supplied buffer, which must be allocated prior to the call
    and it must be at large enough for the requested bytes. Once the
    data is copied, it consumed from the reader.

    @param buf in which to place the data.
    @param len bytes to copy and consume. If 'len' exceeds the bytes
      available to the reader, the number of bytes available is used
      instead.

    @return number of bytes copied and consumed.

  */
  // inkcoreapi int64_t read(void *buf, int64_t len);
  char local_buf[256];   // <- there is a max - LOOK IT UP!
  int64_t reader_len = reader->read(local_buf, ret+1);
  Debug("proxyprotocol_v2", "proto_has_proxy_v2: read [%s] %zu bytes, reader->read() returned:%lld",
          local_buf, strlen(local_buf), reader_len);

  // Now that we know we have a valid PROXY V1 preface, let's parse the
  // remainder of the header

  char * pch;
  int cnt = 0;
  pch = strtok (local_buf," \n\r");
  while (pch!= NULL) {
    switch (cnt) {
      case 0:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = PREFACE",cnt++, pch);
        break;
      // After the PROXY, exactly one space followed by the INET protocol family
      // - TCP4, TCP6 or UNKNOWN
      case 1:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = INET Protocol",cnt++, pch);
        break;
      // Next up is exactly one space and the layer 3 source address
      // - 255.255.255.255 or ffff:f...f:ffff ffff:f...f:fff
      case 2:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = Source Address",cnt++, pch);
        break;
      // Next is exactly one space followed by the layer3 destination address
      // - 255.255.255.255 or ffff:f...f:ffff ffff:f...f:fff
      case 3:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = Destination Address",cnt++, pch);
        break;
      // Next is exactly one space followed by TCP source port represented as a
      //   decimal number in the range of [0..65535] inclusive.
      case 4:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = Source Port",cnt++, pch);
        break;
      // Next is exactly one space followed by TCP destination port represented as a
      //   decimal number in the range of [0..65535] inclusive.
      case 5:
        Debug("proxyprotocol_v2", "proto_has_proxy_v2: token[%d]:[%s] = Destination Port",cnt++, pch);
        break;
    }
    // if we have our 5 fields, we are done here
    if (cnt == 6) {
      break;
    }
    pch = strtok (NULL, " \n\r");
  }

  // Can I then stash this data away somewhere in the structure so it can be
  // retrieved before it gets sent down the stack?

  // Make sure we get the required number of fields
  return (cnt == 6 ? true : false);
}

struct ProtocolProbeTrampoline : public Continuation, public ProtocolProbeSessionAcceptEnums {
  static const size_t minimum_read_size   = 1;
  static const unsigned buffer_size_index = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;
  IOBufferReader *reader;

  explicit ProtocolProbeTrampoline(const ProtocolProbeSessionAccept *probe, Ptr<ProxyMutex> &mutex, MIOBuffer *buffer,
                                   IOBufferReader *reader)
    : Continuation(mutex), probeParent(probe)
  {
    this->iobuf  = buffer ? buffer : new_MIOBuffer(buffer_size_index);
    this->reader = reader ? reader : iobuf->alloc_reader(); // reader must be allocated only on a new MIOBuffer.
    SET_HANDLER(&ProtocolProbeTrampoline::ioCompletionEvent);
  }

  int
  ioCompletionEvent(int event, void *edata)
  {
    VIO *vio;
    NetVConnection *netvc;
    ProtoGroupKey key = N_PROTO_GROUPS; // use this as an invalid value.

    vio   = static_cast<VIO *>(edata);
    netvc = static_cast<NetVConnection *>(vio->vc_server);

    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      // Error ....
      goto done;
    case VC_EVENT_READ_READY:
    case VC_EVENT_READ_COMPLETE:
      break;
    default:
      return EVENT_ERROR;
    }

    ink_assert(netvc != nullptr);

    if (!reader->is_read_avail_more_than(minimum_read_size - 1)) {
      // Not enough data read. Well, that sucks.
      goto done;
    }

    if (proto_has_proxy_v1(reader, netvc)) {
      Debug("http", "ioCompletionEvent: protocol has proxy_v1");
    } else if (proto_has_proxy_v2(reader)) {
      Debug("http", "ioCompletionEvent: protocol has proxy_v2");
    }

    if (proto_is_http2(reader)) {
      Debug("http", "ioCompletionEvent: protocol is http2");
      key = PROTO_HTTP2;
    } else {
      Debug("http", "ioCompletionEvent: protocol is http");
      key = PROTO_HTTP;
    }

    netvc->do_io_read(nullptr, 0, nullptr); // Disable the read IO that we started.

    if (probeParent->endpoint[key] == nullptr) {
      Warning("Unregistered protocol type %d", key);
      goto done;
    }

    // Directly invoke the session acceptor, letting it take ownership of the input buffer.
    if (!probeParent->endpoint[key]->accept(netvc, this->iobuf, reader)) {
      // IPAllow check fails in XxxSessionAccept::accept() if false returned.
      goto done;
    }
    delete this;
    return EVENT_CONT;

  done:
    netvc->do_io_close();
    free_MIOBuffer(this->iobuf);
    this->iobuf = nullptr;
    delete this;
    return EVENT_CONT;
  }

  MIOBuffer *iobuf;
  const ProtocolProbeSessionAccept *probeParent;
};

int
ProtocolProbeSessionAccept::mainEvent(int event, void *data)
{
  if (event == NET_EVENT_ACCEPT) {
    ink_assert(data);

    VIO *vio;
    NetVConnection *netvc          = (NetVConnection *)data;
    ProtocolProbeTrampoline *probe = new ProtocolProbeTrampoline(this, netvc->mutex, nullptr, nullptr);

    // XXX we need to apply accept inactivity timeout here ...

    if (!probe->reader->is_read_avail_more_than(0)) {
      Debug("http", "probe needs data, read..");
      vio = netvc->do_io_read(probe, BUFFER_SIZE_FOR_INDEX(ProtocolProbeTrampoline::buffer_size_index), probe->iobuf);
      vio->reenable();
    } else {
      Debug("http", "probe already has data, call ioComplete directly..");
      vio = netvc->do_io_read(nullptr, 0, nullptr);
      probe->ioCompletionEvent(VC_EVENT_READ_COMPLETE, (void *)vio);
    }
    return EVENT_CONT;
  }

  ink_abort("Protocol probe received a fatal error: errno = %d", -((int)(intptr_t)data));
  return EVENT_CONT;
}

bool
ProtocolProbeSessionAccept::accept(NetVConnection *, MIOBuffer *, IOBufferReader *)
{
  ink_release_assert(0);
  return false;
}

void
ProtocolProbeSessionAccept::registerEndpoint(ProtoGroupKey key, SessionAccept *ap)
{
  ink_release_assert(endpoint[key] == nullptr);
  this->endpoint[key] = ap;
}
