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

#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <string>
#include <cstring>
#include "ts/ts.h"
#include <tsconfig/TsValue.h>
// #include "ts/ink_config.h"
// #include "ts/ink_inet.h"
#include "ipaddr.h"

// typedef std::pair<IpAddr, IpAddr> IpRange;
// typedef std::deque<IpRange> IpRangeQueue;

void Parse_Addr_String(ts::ConstBuffer const &text, IpRange &range);

#endif
