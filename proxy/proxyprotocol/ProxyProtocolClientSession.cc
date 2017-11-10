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

#include "ProxyProtocolClientSession.h"
#include "HttpDebugNames.h"
#include "ts/ink_base64.h"

#define STATE_ENTER(state_name, event)                                                       \
  do {                                                                                       \
    DebugSsn(this, "proxyprotocol_cs", "[%" PRId64 "] [%s, %s]", this->connection_id(), #state_name, \
             HttpDebugNames::get_event_name(event));                                         \
  } while (0)

#define DebugProxyProtocolSsn(fmt, ...) DebugSsn(this, "proxyprotocol_cs", "[%" PRId64 "] " fmt, this->connection_id(), ##__VA_ARGS__)

#define PROXYPROTOCOL_SET_SESSION_HANDLER(handler) \
  do {                                     \
    this->session_handler = (handler);     \
  } while (0)

ClassAllocator<ProxyProtocolClientSession> proxyprotocolClientSessionAllocator("proxyprotocolClientSessionAllocator");

// memcpy the requested bytes from the IOBufferReader, returning how many were
// actually copied.
static inline unsigned
copy_from_buffer_reader(void *dst, IOBufferReader *reader, unsigned nbytes)
{
  char *end;

  end = reader->memcpy(dst, nbytes, 0 /* offset */);
  return end - (char *)dst;
}

static int
send_connection_event(Continuation *cont, int event, void *edata)
{
  SCOPED_MUTEX_LOCK(lock, cont->mutex, this_ethread());
  return cont->handleEvent(event, edata);
}

ProxyProtocolClientSession::ProxyProtocolClientSession()
{
}

void
ProxyProtocolClientSession::destroy()
{
  if (!in_destroy) {
    in_destroy = true;
    DebugProxyProtocolSsn("session destroy");
    // Let everyone know we are going down
    do_api_callout(TS_HTTP_SSN_CLOSE_HOOK);
  }
}

void
ProxyProtocolClientSession::free()
{
  if (h2_pushed_urls) {
    this->h2_pushed_urls = ink_hash_table_destroy(this->h2_pushed_urls);
  }

  if (client_vc) {
    release_netvc();
    client_vc->do_io_close();
    client_vc = nullptr;
  }

  // Make sure the we are at the bottom of the stack
  if (connection_state.is_recursing() || this->recursion != 0) {
    // Note that we are ready to be cleaned up
    // One of the event handlers will catch it
    kill_me = true;
    return;
  }

  DebugProxyProtocolSsn("session free");

  PROXYPROTOCOL_DECREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_CURRENT_CLIENT_SESSION_COUNT, this->mutex->thread_holding);

  // Update stats on how we died.  May want to eliminate this.  Was useful for
  // tracking down which cases we were having problems cleaning up.  But for general
  // use probably not worth the effort
  switch (dying_event) {
  case VC_EVENT_NONE:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_DEFAULT, this_ethread());
    break;
  case VC_EVENT_ACTIVE_TIMEOUT:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_ACTIVE, this_ethread());
    break;
  case VC_EVENT_INACTIVITY_TIMEOUT:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_INACTIVE, this_ethread());
    break;
  case VC_EVENT_ERROR:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_ERROR, this_ethread());
    break;
  case VC_EVENT_EOS:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_EOS, this_ethread());
    break;
  default:
    PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_SESSION_DIE_OTHER, this_ethread());
    break;
  }

  ink_release_assert(this->client_vc == nullptr);

  this->connection_state.destroy();

  super::free();

  free_MIOBuffer(this->read_buffer);
  free_MIOBuffer(this->write_buffer);
  THREAD_FREE(this, proxyprotocolClientSessionAllocator, this_ethread());
}

void
ProxyProtocolClientSession::start()
{
  VIO *read_vio;

  SCOPED_MUTEX_LOCK(lock, this->mutex, this_ethread());

  SET_HANDLER(&ProxyProtocolClientSession::main_event_handler);
  PROXYPROTOCOL_SET_SESSION_HANDLER(&ProxyProtocolClientSession::state_read_connection_preface);

  read_vio  = this->do_io_read(this, INT64_MAX, this->read_buffer);
  write_vio = this->do_io_write(this, INT64_MAX, this->sm_writer);

  // 3.5 HTTP/2 Connection Preface. Upon establishment of a TCP connection and
  // determination that HTTP/2 will be used by both peers, each endpoint MUST
  // send a connection preface as a final confirmation ...
  // this->write_buffer->write(PROXYPROTOCOL_CONNECTION_PREFACE,
  // PROXYPROTOCOL_CONNECTION_PREFACE_LEN);

  this->connection_state.init();
  send_connection_event(&this->connection_state, PROXYPROTOCOL_SESSION_EVENT_INIT, this);
  this->handleEvent(VC_EVENT_READ_READY, read_vio);
}

void
ProxyProtocolClientSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor)
{
  ink_assert(new_vc->mutex->thread_holding == this_ethread());
  PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_CURRENT_CLIENT_SESSION_COUNT, new_vc->mutex->thread_holding);
  PROXYPROTOCOL_INCREMENT_THREAD_DYN_STAT(PROXYPROTOCOL_STAT_TOTAL_CLIENT_CONNECTION_COUNT, new_vc->mutex->thread_holding);

  // HTTP/2 for the backdoor connections? Let's not deal woth that yet.
  ink_release_assert(backdoor == false);

  // Unique client session identifier.
  this->con_id    = ProxyClientSession::next_connection_id();
  this->client_vc = new_vc;
  client_vc->set_inactivity_timeout(HRTIME_SECONDS(ProxyProtocol::accept_no_activity_timeout));
  this->schedule_event = nullptr;
  this->mutex          = new_vc->mutex;
  this->in_destroy     = false;

  this->connection_state.mutex = new_ProxyMutex();

  DebugProxyProtocolSsn("session born, netvc %p", this->client_vc);

  this->client_vc->set_tcp_congestion_control(CLIENT_SIDE);

  this->read_buffer             = iobuf ? iobuf : new_MIOBuffer(PROXYPROTOCOL_HEADER_BUFFER_SIZE_INDEX);
  this->read_buffer->water_mark = connection_state.server_settings.get(PROXYPROTOCOL_SETTINGS_MAX_FRAME_SIZE);
  this->sm_reader               = reader ? reader : this->read_buffer->alloc_reader();
  this->h2_pushed_urls          = ink_hash_table_create(InkHashTableKeyType_String);
  this->h2_pushed_urls_size     = 0;

  this->write_buffer = new_MIOBuffer(PROXYPROTOCOL_HEADER_BUFFER_SIZE_INDEX);
  this->sm_writer    = this->write_buffer->alloc_reader();

  do_api_callout(TS_HTTP_SSN_START_HOOK);
}

void
ProxyProtocolClientSession::set_upgrade_context(HTTPHdr *h)
{
  upgrade_context.req_header = new HTTPHdr();
  upgrade_context.req_header->copy(h);

  MIMEField *settings = upgrade_context.req_header->field_find(MIME_FIELD_PROXYPROTOCOL_SETTINGS, MIME_LEN_PROXYPROTOCOL_SETTINGS);
  ink_release_assert(settings != nullptr);
  int svlen;
  const char *sv = settings->value_get(&svlen);

  // Maybe size of data decoded by Base64URL is lower than size of encoded data.
  unsigned char out_buf[svlen];
  if (sv && svlen > 0) {
    size_t decoded_len;
    ats_base64_decode(sv, svlen, out_buf, svlen, &decoded_len);
    for (size_t nbytes = 0; nbytes < decoded_len; nbytes += PROXYPROTOCOL_SETTINGS_PARAMETER_LEN) {
      ProxyProtocolSettingsParameter param;
      if (!proxyprotocol_parse_settings_parameter(make_iovec(out_buf + nbytes, PROXYPROTOCOL_SETTINGS_PARAMETER_LEN), param) ||
          !proxyprotocol_settings_parameter_is_valid(param)) {
        // TODO ignore incoming invalid parameters and send suitable SETTINGS
        // frame.
      }
      upgrade_context.client_settings.set(static_cast<ProxyProtocolSettingsIdentifier>(param.id), param.value);
    }
  }

  // Such intermediaries SHOULD also remove other connection-
  // specific header fields, such as Keep-Alive, Proxy-Connection,
  // Transfer-Encoding and Upgrade, even if they are not nominated by
  // Connection.
  upgrade_context.req_header->field_delete(MIME_FIELD_CONNECTION, MIME_LEN_CONNECTION);
  upgrade_context.req_header->field_delete(MIME_FIELD_KEEP_ALIVE, MIME_LEN_KEEP_ALIVE);
  upgrade_context.req_header->field_delete(MIME_FIELD_PROXY_CONNECTION, MIME_LEN_PROXY_CONNECTION);
  upgrade_context.req_header->field_delete(MIME_FIELD_TRANSFER_ENCODING, MIME_LEN_TRANSFER_ENCODING);
  upgrade_context.req_header->field_delete(MIME_FIELD_UPGRADE, MIME_LEN_UPGRADE);
  upgrade_context.req_header->field_delete(MIME_FIELD_PROXYPROTOCOL_SETTINGS, MIME_LEN_PROXYPROTOCOL_SETTINGS);
}

VIO *
ProxyProtocolClientSession::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  return this->client_vc->do_io_read(c, nbytes, buf);
}

VIO *
ProxyProtocolClientSession::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  return this->client_vc->do_io_write(c, nbytes, buf, owner);
}

void
ProxyProtocolClientSession::do_io_shutdown(ShutdownHowTo_t howto)
{
  this->client_vc->do_io_shutdown(howto);
}

// XXX Currently, we don't have a half-closed state, but we will need to
// implement that. After we send a GOAWAY, there
// are scenarios where we would like to complete the outstanding streams.

void
ProxyProtocolClientSession::do_io_close(int alerrno)
{
  DebugProxyProtocolSsn("session closed");

  ink_assert(this->mutex->thread_holding == this_ethread());
  send_connection_event(&this->connection_state, PROXYPROTOCOL_SESSION_EVENT_FINI, this);

  // Don't send the SSN_CLOSE_HOOK until we got rid of all the streams
  // And handled all the TXN_CLOSE_HOOK's
  if (client_vc) {
    // Copy aside the client address before releasing the vc
    cached_client_addr.assign(client_vc->get_remote_addr());
    cached_local_addr.assign(client_vc->get_local_addr());
    this->release_netvc();
    client_vc->do_io_close();
    client_vc = nullptr;
  }

  {
    SCOPED_MUTEX_LOCK(lock, this->connection_state.mutex, this_ethread());
    this->connection_state.release_stream(nullptr);
  }
}

void
ProxyProtocolClientSession::reenable(VIO *vio)
{
  this->client_vc->reenable(vio);
}

void
ProxyProtocolClientSession::set_half_close_local_flag(bool flag)
{
  if (!half_close_local && flag) {
    DebugProxyProtocolSsn("session half-close local");
  }
  half_close_local = flag;
}

int
ProxyProtocolClientSession::main_event_handler(int event, void *edata)
{
  ink_assert(this->mutex->thread_holding == this_ethread());
  int retval;

  recursion++;

  Event *e = static_cast<Event *>(edata);
  if (e == schedule_event) {
    schedule_event = nullptr;
  }

  if (proxyprotocol_drain && this->connection_state.get_shutdown_state() == NOT_INITIATED) {
    send_connection_event(&this->connection_state, PROXYPROTOCOL_SESSION_EVENT_SHUTDOWN_INIT, this);
  }

  switch (event) {
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_READ_READY:
    retval = (this->*session_handler)(event, edata);
    break;

  case PROXYPROTOCOL_SESSION_EVENT_XMIT: {
    ProxyProtocolFrame *frame = (ProxyProtocolFrame *)edata;
    total_write_len += frame->size();
    write_vio->nbytes = total_write_len;
    frame->xmit(this->write_buffer);
    write_reenable();
    retval = 0;
    break;
  }

  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ERROR:
  case VC_EVENT_EOS:
    this->do_io_close();
    retval = 0;
    break;

  case VC_EVENT_WRITE_READY:
    retval = 0;
    break;

  case VC_EVENT_WRITE_COMPLETE:
    // Seems as this is being closed already
    retval = 0;
    break;

  default:
    DebugProxyProtocolSsn("unexpected event=%d edata=%p", event, edata);
    ink_release_assert(0);
    retval = 0;
    break;
  }
  recursion--;
  if (!connection_state.is_recursing() && this->recursion == 0 && kill_me) {
    this->free();
  }
  return retval;
}

int
ProxyProtocolClientSession::state_read_connection_preface(int event, void *edata)
{
  VIO *vio = (VIO *)edata;

  STATE_ENTER(&ProxyProtocolClientSession::state_read_connection_preface, event);
  ink_assert(event == VC_EVENT_READ_COMPLETE || event == VC_EVENT_READ_READY);

  if (this->sm_reader->read_avail() >= (int64_t)PROXYPROTOCOL_CONNECTION_PREFACE_LEN) {
    char buf[PROXYPROTOCOL_CONNECTION_PREFACE_LEN];
    unsigned nbytes;

    nbytes = copy_from_buffer_reader(buf, this->sm_reader, sizeof(buf));
    ink_release_assert(nbytes == PROXYPROTOCOL_CONNECTION_PREFACE_LEN);

    if (memcmp(PROXYPROTOCOL_CONNECTION_PREFACE, buf, nbytes) != 0) {
      DebugProxyProtocolSsn("invalid connection preface");
      this->do_io_close();
      return 0;
    }

    DebugProxyProtocolSsn("received connection preface");
    this->sm_reader->consume(nbytes);
    PROXYPROTOCOL_SET_SESSION_HANDLER(&ProxyProtocolClientSession::state_start_frame_read);

    client_vc->set_inactivity_timeout(HRTIME_SECONDS(ProxyProtocol::no_activity_timeout_in));
    client_vc->set_active_timeout(HRTIME_SECONDS(ProxyProtocol::active_timeout_in));

    // XXX start the write VIO ...

    // If we have unconsumed data, start tranferring frames now.
    if (this->sm_reader->is_read_avail_more_than(0)) {
      return this->handleEvent(VC_EVENT_READ_READY, vio);
    }
  }

  // XXX We don't have enough data to check the connection preface. We should
  // reset the accept inactivity
  // timeout. We should have a maximum timeout to get the session started
  // though.

  vio->reenable();
  return 0;
}

int
ProxyProtocolClientSession::state_start_frame_read(int event, void *edata)
{
  VIO *vio = (VIO *)edata;

  STATE_ENTER(&ProxyProtocolClientSession::state_start_frame_read, event);
  ink_assert(event == VC_EVENT_READ_COMPLETE || event == VC_EVENT_READ_READY);
  return state_process_frame_read(event, vio, false);
}

int
ProxyProtocolClientSession::do_start_frame_read(ProxyProtocolErrorCode &ret_error)
{
  ret_error = ProxyProtocolErrorCode::PROXYPROTOCOL_ERROR_NO_ERROR;
  ink_release_assert(this->sm_reader->read_avail() >= (int64_t)PROXYPROTOCOL_FRAME_HEADER_LEN);

  uint8_t buf[PROXYPROTOCOL_FRAME_HEADER_LEN];
  unsigned nbytes;

  DebugProxyProtocolSsn("receiving frame header");
  nbytes = copy_from_buffer_reader(buf, this->sm_reader, sizeof(buf));

  if (!proxyprotocol_parse_frame_header(make_iovec(buf), this->current_hdr)) {
    DebugProxyProtocolSsn("frame header parse failure");
    this->do_io_close();
    return -1;
  }

  DebugProxyProtocolSsn("frame header length=%u, type=%u, flags=0x%x, streamid=%u", (unsigned)this->current_hdr.length,
                (unsigned)this->current_hdr.type, (unsigned)this->current_hdr.flags, this->current_hdr.streamid);

  this->sm_reader->consume(nbytes);

  if (!proxyprotocol_frame_header_is_valid(this->current_hdr, this->connection_state.server_settings.get(PROXYPROTOCOL_SETTINGS_MAX_FRAME_SIZE))) {
    ret_error = ProxyProtocolErrorCode::PROXYPROTOCOL_ERROR_PROTOCOL_ERROR;
    return -1;
  }

  // If we know up front that the payload is too long, nuke this connection.
  if (this->current_hdr.length > this->connection_state.server_settings.get(PROXYPROTOCOL_SETTINGS_MAX_FRAME_SIZE)) {
    ret_error = ProxyProtocolErrorCode::PROXYPROTOCOL_ERROR_FRAME_SIZE_ERROR;
    return -1;
  }

  // CONTINUATIONs MUST follow behind HEADERS which doesn't have END_HEADERS
  ProxyProtocolStreamId continued_stream_id = this->connection_state.get_continued_stream_id();

  if (continued_stream_id != 0 &&
      (continued_stream_id != this->current_hdr.streamid || this->current_hdr.type != PROXYPROTOCOL_FRAME_TYPE_CONTINUATION)) {
    ret_error = ProxyProtocolErrorCode::PROXYPROTOCOL_ERROR_PROTOCOL_ERROR;
    return -1;
  }
  return 0;
}

int
ProxyProtocolClientSession::state_complete_frame_read(int event, void *edata)
{
  VIO *vio = (VIO *)edata;
  STATE_ENTER(&ProxyProtocolClientSession::state_complete_frame_read, event);
  ink_assert(event == VC_EVENT_READ_COMPLETE || event == VC_EVENT_READ_READY);
  if (this->sm_reader->read_avail() < this->current_hdr.length) {
    vio->reenable();
    return 0;
  }
  DebugProxyProtocolSsn("completed frame read, %" PRId64 " bytes available", this->sm_reader->read_avail());

  return state_process_frame_read(event, vio, true);
}

int
ProxyProtocolClientSession::do_complete_frame_read()
{
  // XXX parse the frame and handle it ...
  ink_release_assert(this->sm_reader->read_avail() >= this->current_hdr.length);

  ProxyProtocolFrame frame(this->current_hdr, this->sm_reader);
  send_connection_event(&this->connection_state, PROXYPROTOCOL_SESSION_EVENT_RECV, &frame);
  this->sm_reader->consume(this->current_hdr.length);

  // Set the event handler if there is no more data to process a new frame
  PROXYPROTOCOL_SET_SESSION_HANDLER(&ProxyProtocolClientSession::state_start_frame_read);

  return 0;
}

int
ProxyProtocolClientSession::state_process_frame_read(int event, VIO *vio, bool inside_frame)
{
  if (inside_frame) {
    do_complete_frame_read();
  }

  while (this->sm_reader->read_avail() >= (int64_t)PROXYPROTOCOL_FRAME_HEADER_LEN) {
    // Return if there was an error
    ProxyProtocolErrorCode err;
    if (do_start_frame_read(err) < 0) {
      // send an error if specified.  Otherwise, just go away
      if (err > ProxyProtocolErrorCode::PROXYPROTOCOL_ERROR_NO_ERROR) {
        SCOPED_MUTEX_LOCK(lock, this->connection_state.mutex, this_ethread());
        if (!this->connection_state.is_state_closed()) {
          this->connection_state.send_goaway_frame(this->connection_state.get_latest_stream_id_in(), err);
          this->set_half_close_local_flag(true);
          this->do_io_close();
        }
      }
      return 0;
    }

    // If there is no more data to finish the frame, set up the event handler and reenable
    if (this->sm_reader->read_avail() < this->current_hdr.length) {
      PROXYPROTOCOL_SET_SESSION_HANDLER(&ProxyProtocolClientSession::state_complete_frame_read);
      break;
    }
    do_complete_frame_read();
  }

  // If the client hasn't shut us down, reenable
  if (!this->is_client_closed()) {
    vio->reenable();
  }
  return 0;
}
