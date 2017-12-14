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
//#include "ProxyProtocolConnectionState.h"
#include <ts/string_view.h>
#include <ts/ink_inet.h>

class ProxyProtocolClientSession;
typedef int (*ProxyProtocolClientSessionHandler)(TSCont contp, TSEvent event, void *data);

class ProxyProtocolRequest
{
public:
  ProxyProtocolRequest()
    : event(0),
      proxyprotocol_sm(NULL),
      stream_id(-1),
      start_time(0),
      fetch_sm(NULL),
      has_submitted_data(false),
      need_resume_data(false),
      fetch_data_len(0),
      delta_window_size(0),
      fetch_body_completed(false)
  {
  }

  ProxyProtocolRequest(ProxyProtocolClientSession *sm, int id)
    : event(0),
      proxyprotocol_sm(NULL),
      stream_id(-1),
      start_time(0),
      fetch_sm(NULL),
      has_submitted_data(false),
      need_resume_data(false),
      fetch_data_len(0),
      delta_window_size(0),
      fetch_body_completed(false)
  {
    init(sm, id);
  }

  void init(ProxyProtocolClientSession *sm, int id);
  void clear();

  static ProxyProtocolRequest *alloc();
  //void destroy();

  void
  append_nv(char **nv)
  {
    for (int i = 0; nv[i]; i += 2) {
      headers.push_back(std::make_pair(nv[i], nv[i + 1]));
    }
  }

public:
  int event;
  ProxyProtocolClientSession *proxyprotocol_sm;
  int stream_id;
  TSHRTime start_time;
  TSFetchSM fetch_sm;
  bool has_submitted_data;
  bool need_resume_data;
  int fetch_data_len;
  unsigned delta_window_size;
  bool fetch_body_completed;
  std::vector<std::pair<std::string, std::string>> headers;

  std::string url;
  std::string host;
  std::string path;
  std::string scheme;
  std::string method;
  std::string version;

  MD5_CTX recv_md5;
};


// class ProxyProtocolClientSession : public Continuation, public PluginIdentity
class ProxyProtocolClientSession : public ProxyClientSession, public PluginIdentity
{
public:
  typedef ProxyClientSession super; ///< Parent type.
  typedef int (ProxyProtocolClientSession::*SessionHandler)(int, void *);
//  ProxyProtocolClientSession()
//    : sm_id(0),
//      //version(spdy::SessionVersion::SESSION_VERSION_3_1),
//      total_size(0),
//      start_time(0),
//      vc(NULL),
//      req_buffer(NULL),
//      req_reader(NULL),
//      resp_buffer(NULL),
//      resp_reader(NULL),
//      read_vio(NULL),
//      write_vio(NULL),
//      event(0)
//      // session(NULL)
//  {
//  }

  void init(NetVConnection *netvc);
  void clear();
  void destroy() override;
  void free() override;
  void start() override;

  static ProxyProtocolClientSession *alloc();

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

  //void
  //start()
  //{
  //  ink_release_assert(false);
  //}

  //void do_io_close(int lerrno = -1);
  //void
  //do_io_shutdown(ShutdownHowTo_t howto)
  //{
  //  ink_release_assert(false);
  //}
  //NetVConnection *
  //get_netvc() const
  //{
  //  return vc;
  //}
  //void
  //release_netvc()
  //{
  //  vc = NULL;
  //}
  
  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor) override;

  int
  get_transact_count() const override
  {
    return this->transact_count;
  }
  void
  release(ProxyClientTransaction *) override
  { /* TBD */
  }

  const char *
  get_protocol_string() const override
  {
    return "http/2";
  }

  int64_t sm_id;
  //spdy::SessionVersion version;
  uint64_t total_size;
  TSHRTime start_time;

  NetVConnection *vc;

  TSIOBuffer req_buffer;
  TSIOBufferReader req_reader;

  TSIOBuffer resp_buffer;
  TSIOBufferReader resp_reader;

  VIO *read_vio;
  VIO *write_vio;

  int event;
  //spdylay_session *session;
  int transact_count;

  //Map<int32_t, ProxyProtocolRequest *> req_map;

  ////virtual char const *getPluginTag() const;
  ////virtual int64_t getPluginId() const;

  //ProxyProtocolRequest *
  //find_request(int streamId)
  //{
  //  Map<int32_t, ProxyProtocolRequest *>::iterator iter = this->req_map.find(streamId);
  //  return ((iter == this->req_map.end()) ? NULL : iter->second);
  //}

  //void
  //cleanup_request(int streamId)
  //{
  //  ProxyProtocolRequest *req = this->find_request(streamId);
  //  if (req) {
  //    req->destroy();
  //    this->req_map.erase(streamId);
  //  }
  //  if (req_map.empty() == true) {
  //    vc->add_to_keep_alive_queue();
  //  }
  //}

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

private:
  int main_event_handler(int, void *);
  int state_read_connection_preface(int, void *);

  NetVConnection *client_vc      = nullptr;
  MIOBuffer *read_buffer         = nullptr;
  IOBufferReader *sm_reader      = nullptr;
  MIOBuffer *write_buffer        = nullptr;
  IOBufferReader *sm_writer      = nullptr;
  SessionHandler session_handler = nullptr;

  IpEndpoint cached_client_addr;
  IpEndpoint cached_local_addr;

  int state_session_start(int event, void *edata);
  int state_session_readwrite(int event, void *edata);
};

extern ClassAllocator<ProxyProtocolClientSession> proxyprotocolClientSessionAllocator;

#endif
