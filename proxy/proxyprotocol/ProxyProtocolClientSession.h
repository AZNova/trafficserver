/** @file

  ProxyProtocolClientSession.

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

#ifndef __PROXYPROTOCOL_CLIENT_SESSION_H__
#define __PROXYPROTOCOL_CLIENT_SESSION_H__

#include "ProxyProtocol.h"
#include "Plugin.h"
#include "ProxyClientSession.h"
#include "ProxyProtocolConnectionState.h"
#include <ts/string_view.h>
#include <ts/ink_inet.h>

// Name                       Edata                 Description
// PROXYPROTOCOL_SESSION_EVENT_INIT   ProxyProtocolClientSession *  Proxy Protocol session is born
// PROXYPROTOCOL_SESSION_EVENT_FINI   ProxyProtocolClientSession *  Proxy Protocol session is ended
// PROXYPROTOCOL_SESSION_EVENT_RECV   ProxyProtocolFrame *          Received a frame
// PROXYPROTOCOL_SESSION_EVENT_XMIT   ProxyProtocolFrame *          Send this frame

#define PROXYPROTOCOL_SESSION_EVENT_INIT (PROXYPROTOCOL_SESSION_EVENTS_START + 1)
#define PROXYPROTOCOL_SESSION_EVENT_FINI (PROXYPROTOCOL_SESSION_EVENTS_START + 2)
#define PROXYPROTOCOL_SESSION_EVENT_RECV (PROXYPROTOCOL_SESSION_EVENTS_START + 3)
#define PROXYPROTOCOL_SESSION_EVENT_XMIT (PROXYPROTOCOL_SESSION_EVENTS_START + 4)
#define PROXYPROTOCOL_SESSION_EVENT_SHUTDOWN_INIT (PROXYPROTOCOL_SESSION_EVENTS_START + 5)
#define PROXYPROTOCOL_SESSION_EVENT_SHUTDOWN_CONT (PROXYPROTOCOL_SESSION_EVENTS_START + 6)

size_t const PROXYPROTOCOL_HEADER_BUFFER_SIZE_INDEX = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;

// To support Upgrade: h2c
struct ProxyProtocolUpgradeContext {
  ProxyProtocolUpgradeContext() : req_header(NULL) {}
  ~ProxyProtocolUpgradeContext()
  {
    if (req_header) {
      req_header->clear();
      delete req_header;
    }
  }

  // Modified request header
  HTTPHdr *req_header;

  // Decoded ProxyProtocol-Settings Header Field
  ProxyProtocolConnectionSettings client_settings;
};

class ProxyProtocolFrame
{
public:
  ProxyProtocolFrame(const ProxyProtocolFrameHeader &h, IOBufferReader *r)
  {
    this->hdr      = h;
    this->ioreader = r;
  }

  ProxyProtocolFrame(ProxyProtocolFrameType type, ProxyProtocolStreamId streamid, uint8_t flags)
  {
    this->hdr      = {0, (uint8_t)type, flags, streamid};
    this->ioreader = NULL;
  }

  IOBufferReader *
  reader() const
  {
    return ioreader;
  }

  const ProxyProtocolFrameHeader &
  header() const
  {
    return this->hdr;
  }

  // Allocate an IOBufferBlock for payload of this frame.
  void
  alloc(int index)
  {
    this->ioblock = new_IOBufferBlock();
    this->ioblock->alloc(index);
  }

  // Return the writeable buffer space for frame payload
  IOVec
  write()
  {
    return make_iovec(this->ioblock->end(), this->ioblock->write_avail());
  }

  // Once the frame has been serialized, update the payload length of frame header.
  void
  finalize(size_t nbytes)
  {
    if (this->ioblock) {
      ink_assert((int64_t)nbytes <= this->ioblock->write_avail());
      this->ioblock->fill(nbytes);

      this->hdr.length = this->ioblock->size();
    }
  }

  void
  xmit(MIOBuffer *iobuffer)
  {
    // Write frame header
    uint8_t buf[PROXYPROTOCOL_FRAME_HEADER_LEN];
    proxyprotocol_write_frame_header(hdr, make_iovec(buf));
    iobuffer->write(buf, sizeof(buf));

    // Write frame payload
    // It could be empty (e.g. SETTINGS frame with ACK flag)
    if (ioblock && ioblock->read_avail() > 0) {
      iobuffer->append_block(this->ioblock.get());
    }
  }

  int64_t
  size()
  {
    if (ioblock) {
      return PROXYPROTOCOL_FRAME_HEADER_LEN + ioblock->size();
    } else {
      return PROXYPROTOCOL_FRAME_HEADER_LEN;
    }
  }

  // noncopyable
  ProxyProtocolFrame(ProxyProtocolFrame &) = delete;
  ProxyProtocolFrame &operator=(const ProxyProtocolFrame &) = delete;

private:
  ProxyProtocolFrameHeader hdr;       // frame header
  Ptr<IOBufferBlock> ioblock; // frame payload
  IOBufferReader *ioreader;
};

class ProxyProtocolClientSession : public ProxyClientSession
{
public:
  typedef ProxyClientSession super; ///< Parent type.
  typedef int (ProxyProtocolClientSession::*SessionHandler)(int, void *);

  ProxyProtocolClientSession();

  // Implement ProxyClientSession interface.
  void start() override;
  void destroy() override;
  void free() override;
  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor) override;

  bool
  ready_to_free() const
  {
    return kill_me;
  }

  // Implement VConnection interface.
  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0) override;
  VIO *do_io_write(Continuation *c = NULL, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false) override;
  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;
  void reenable(VIO *vio) override;

  NetVConnection *
  get_netvc() const override
  {
    return client_vc;
  }

  void
  release_netvc() override
  {
    // Make sure the vio's are also released to avoid later surprises in inactivity timeout
    if (client_vc) {
      client_vc->do_io_read(NULL, 0, NULL);
      client_vc->do_io_write(NULL, 0, NULL);
      client_vc->set_action(NULL);
    }
  }

  sockaddr const *
  get_client_addr() override
  {
    return client_vc ? client_vc->get_remote_addr() : &cached_client_addr.sa;
  }

  sockaddr const *
  get_local_addr() override
  {
    return client_vc ? client_vc->get_local_addr() : &cached_local_addr.sa;
  }

  void
  write_reenable()
  {
    write_vio->reenable();
  }

  void set_upgrade_context(HTTPHdr *h);

  const ProxyProtocolUpgradeContext &
  get_upgrade_context() const
  {
    return upgrade_context;
  }

  int
  get_transact_count() const override
  {
    return connection_state.get_stream_requests();
  }

  void
  release(ProxyClientTransaction *trans) override
  {
  }

  ProxyProtocolConnectionState connection_state;
  void
  set_dying_event(int event)
  {
    dying_event = event;
  }

  int
  get_dying_event() const
  {
    return dying_event;
  }

  bool
  is_recursing() const
  {
    return recursion > 0;
  }

  const char *
  get_protocol_string() const override
  {
    return "http/2";
  }

  virtual int
  populate_protocol(ts::string_view *result, int size) const override
  {
    int retval = 0;
    if (size > retval) {
      result[retval++] = IP_PROTO_TAG_PROXY;
      if (size > retval) {
        retval += super::populate_protocol(result + retval, size - retval);
      }
    }
    return retval;
  }

  virtual const char *
  protocol_contains(ts::string_view prefix) const override
  {
    const char *retval = nullptr;

    if (prefix.size() <= IP_PROTO_TAG_PROXY.size() && strncmp(IP_PROTO_TAG_PROXY.data(), prefix.data(), prefix.size()) == 0) {
      retval = IP_PROTO_TAG_PROXY.data();
    } else {
      retval = super::protocol_contains(prefix);
    }
    return retval;
  }

  void set_half_close_local_flag(bool flag);
  bool
  get_half_close_local_flag() const
  {
    return half_close_local;
  }

  bool
  is_url_pushed(const char *url, int url_len)
  {
    char *dup_url            = ats_strndup(url, url_len);
    InkHashTableEntry *entry = ink_hash_table_lookup_entry(h2_pushed_urls, dup_url);
    ats_free(dup_url);
    return entry != nullptr;
  }

  void
  add_url_to_pushed_table(const char *url, int url_len)
  {
    if (h2_pushed_urls_size < ProxyProtocol::push_diary_size) {
      char *dup_url = ats_strndup(url, url_len);
      ink_hash_table_insert(h2_pushed_urls, dup_url, nullptr);
      h2_pushed_urls_size++;
      ats_free(dup_url);
    }
  }

  // noncopyable
  ProxyProtocolClientSession(ProxyProtocolClientSession &) = delete;
  ProxyProtocolClientSession &operator=(const ProxyProtocolClientSession &) = delete;

private:
  int main_event_handler(int, void *);

  int state_read_connection_preface(int, void *);
  int state_start_frame_read(int, void *);
  int do_start_frame_read(ProxyProtocolErrorCode &ret_error);
  int state_complete_frame_read(int, void *);
  int do_complete_frame_read();
  // state_start_frame_read and state_complete_frame_read are set up as
  // event handler.  Both feed into state_process_frame_read which may iterate
  // if there are multiple frames ready on the wire
  int state_process_frame_read(int event, VIO *vio, bool inside_frame);

  int64_t total_write_len        = 0;
  SessionHandler session_handler = nullptr;
  NetVConnection *client_vc      = nullptr;
  MIOBuffer *read_buffer         = nullptr;
  IOBufferReader *sm_reader      = nullptr;
  MIOBuffer *write_buffer        = nullptr;
  IOBufferReader *sm_writer      = nullptr;
  ProxyProtocolFrameHeader current_hdr   = {0, 0, 0, 0};

  IpEndpoint cached_client_addr;
  IpEndpoint cached_local_addr;

  // For Upgrade: h2c
  ProxyProtocolUpgradeContext upgrade_context;

  VIO *write_vio        = nullptr;
  int dying_event       = 0;
  bool kill_me          = false;
  bool half_close_local = false;
  int recursion         = 0;

  InkHashTable *h2_pushed_urls = nullptr;
  uint32_t h2_pushed_urls_size = 0;
};

extern ClassAllocator<ProxyProtocolClientSession> proxyProtocolClientSessionAllocator;

#endif // __PROXYPROTOCOL_CLIENT_SESSION_H__
