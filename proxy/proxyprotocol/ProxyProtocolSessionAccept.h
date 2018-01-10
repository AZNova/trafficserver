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

#ifndef __PROXYPROTOCOL_SESSION_ACCEPT_H__
#define __PROXYPROTOCOL_SESSION_ACCEPT_H__

#include "ts/ink_platform.h"
#include "I_Net.h"

#include "http/HttpSessionAccept.h"
#include "P_SSLNextProtocolAccept.h"

//struct ProxyProtocolSessionAccept : public SessionAccept {
struct ProxyProtocolSessionAccept : public SSLNextProtocolAccept 
{
  //ProxyProtocolSessionAccept(Continuation *, bool);
  ProxyProtocolSessionAccept(Continuation *ep, bool transparent_passthrough)
    : SSLNextProtocolAccept(ep, transparent_passthrough), buffer(new_empty_MIOBuffer()), endpoint(ep), 
      transparent_passthrough(transparent_passthrough)
    
  {
    this->iobuf  = buffer ? buffer : new_MIOBuffer(buffer_size_index);
    this->reader = reader ? reader : iobuf->alloc_reader(); // reader must be allocated only on a new MIOBuffer.
    SET_HANDLER(&ProxyProtocolSessionAccept::mainEvent);
  }

  //explicit ProxyProtocolSessionAccept(const HttpSessionAccept::Options &);
  ~ProxyProtocolSessionAccept();

  bool accept(NetVConnection *, MIOBuffer *, IOBufferReader *);
  int mainEvent(int event, void *netvc);

  bool registerEndpoint(const char *protocol, Continuation *handler);
  //void registerEndpoint(SessionAccept *ap);

  // noncopyable
  ProxyProtocolSessionAccept(const ProxyProtocolSessionAccept &) = delete;
  ProxyProtocolSessionAccept &operator=(const ProxyProtocolSessionAccept &) = delete;

  //IOBufferReader *reader;

  SSLNextProtocolAccept *ssl_next;
  SSLNextProtocolSet *protoset;

  bool
  getTransparentPassthrough()
  {
    return transparent_passthrough;
  }

private:
  static const unsigned buffer_size_index = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;
  MIOBuffer *buffer;
  MIOBuffer *iobuf;
  IOBufferReader *reader;
  //Continuation *endpoint;
  //  this->iobuf  = buffer ? buffer : new_MIOBuffer(buffer_size_index);
  //  this->reader = reader ? reader : iobuf->alloc_reader(); // reader must be allocated only on a new MIOBuffer.
  HttpSessionAccept::Options options;
  //SessionAccept *endpoint;
  Continuation *endpoint;
  bool transparent_passthrough;
};

#endif // __PROXYPROTOCOL_SESSION_ACCEPT_H__
