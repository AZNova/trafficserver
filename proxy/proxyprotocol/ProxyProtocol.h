/** @file

  ProxyProtocol

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

#ifndef ProxyProtocol_H_
#define ProxyProtocol_H_

// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

// 2.2. Binary header format (version 2)
//
// Producing human-readable IPv6 addresses and parsing them is very inefficient,
// due to the multiple possible representation formats and the handling of compact
// address format. It was also not possible to specify address families outside
// IPv4/IPv6 nor non-TCP protocols. Another drawback of the human-readable format
// is the fact that implementations need to parse all characters to find the
// trailing CRLF, which makes it harder to read only the exact bytes count. Last,
// the UNKNOWN address type has not always been accepted by servers as a valid
// protocol because of its imprecise meaning.
//
// Version 2 of the protocol thus introduces a new binary format which remains
// distinguishable from version 1 and from other commonly used protocols. It was
// specially designed in order to be incompatible with a wide range of protocols
// and to be rejected by a number of common implementations of these protocols
// when unexpectedly presented (please see section 7). Also for better processing
// efficiency, IPv4 and IPv6 addresses are respectively aligned on 4 and 16 bytes
// boundaries.
//
// The binary header format starts with a constant 12 bytes block containing the
// protocol signature :
//
//    \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A
//
// Note that this block contains a null byte at the 5th position, so it must not
// be handled as a null-terminated string.
//
// The next byte (the 13th one) is the protocol version and command.
//
// The highest four bits contains the version. As of this specification, it must
// always be sent as \x2 and the receiver must only accept this value.
//
// The lowest four bits represents the command :
//   - \x0 : LOCAL : the connection was established on purpose by the proxy
//     without being relayed. The connection endpoints are the sender and the
//     receiver. Such connections exist when the proxy sends health-checks to the
//     server. The receiver must accept this connection as valid and must use the
//     real connection endpoints and discard the protocol block including the
//     family which is ignored.
//
//   - \x1 : PROXY : the connection was established on behalf of another node,
//     and reflects the original connection endpoints. The receiver must then use
//     the information provided in the protocol block to get original the address.
//
//   - other values are unassigned and must not be emitted by senders. Receivers
//     must drop connections presenting unexpected values here.
//
// The 14th byte contains the transport protocol and address family. The highest 4
// bits contain the address family, the lowest 4 bits contain the protocol.
//
// The address family maps to the original socket family without necessarily
// matching the values internally used by the system. It may be one of :
//
//   - 0x0 : AF_UNSPEC : the connection is forwarded for an unknown, unspecified
//     or unsupported protocol. The sender should use this family when sending
//     LOCAL commands or when dealing with unsupported protocol families. The
//     receiver is free to accept the connection anyway and use the real endpoint
//     addresses or to reject it. The receiver should ignore address information.
//
//   - 0x1 : AF_INET : the forwarded connection uses the AF_INET address family
//     (IPv4). The addresses are exactly 4 bytes each in network byte order,
//     followed by transport protocol information (typically ports).
//
//   - 0x2 : AF_INET6 : the forwarded connection uses the AF_INET6 address family
//     (IPv6). The addresses are exactly 16 bytes each in network byte order,
//     followed by transport protocol information (typically ports).
//
//   - 0x3 : AF_UNIX : the forwarded connection uses the AF_UNIX address family
//     (UNIX). The addresses are exactly 108 bytes each.
//
//   - other values are unspecified and must not be emitted in version 2 of this
//     protocol and must be rejected as invalid by receivers.
//
// The transport protocol is specified in the lowest 4 bits of the 14th byte :
//
//   - 0x0 : UNSPEC : the connection is forwarded for an unknown, unspecified
//     or unsupported protocol. The sender should use this family when sending
//     LOCAL commands or when dealing with unsupported protocol families. The
//     receiver is free to accept the connection anyway and use the real endpoint
//     addresses or to reject it. The receiver should ignore address information.
//
//   - 0x1 : STREAM : the forwarded connection uses a SOCK_STREAM protocol (eg:
//     TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the addresses
//     are followed by the source and destination ports represented on 2 bytes
//     each in network byte order.
//
//   - 0x2 : DGRAM : the forwarded connection uses a SOCK_DGRAM protocol (eg:
//     UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6 (UDP), the addresses
//     are followed by the source and destination ports represented on 2 bytes
//     each in network byte order.
//
//   - other values are unspecified and must not be emitted in version 2 of this
//     protocol and must be rejected as invalid by receivers.
//
// In practice, the following protocol bytes are expected :
//
//   - \x00 : UNSPEC : the connection is forwarded for an unknown, unspecified
//     or unsupported protocol. The sender should use this family when sending
//     LOCAL commands or when dealing with unsupported protocol families. When
//     used with a LOCAL command, the receiver must accept the connection and
//     ignore any address information. For other commands, the receiver is free
//     to accept the connection anyway and use the real endpoints addresses or to
//     reject the connection. The receiver should ignore address information.
//
//   - \x11 : TCP over IPv4 : the forwarded connection uses TCP over the AF_INET
//     protocol family. Address length is 2*4 + 2*2 = 12 bytes.
//
//   - \x12 : UDP over IPv4 : the forwarded connection uses UDP over the AF_INET
//     protocol family. Address length is 2*4 + 2*2 = 12 bytes.
//
//   - \x21 : TCP over IPv6 : the forwarded connection uses TCP over the AF_INET6
//     protocol family. Address length is 2*16 + 2*2 = 36 bytes.
//
//   - \x22 : UDP over IPv6 : the forwarded connection uses UDP over the AF_INET6
//     protocol family. Address length is 2*16 + 2*2 = 36 bytes.
//
//   - \x31 : UNIX stream : the forwarded connection uses SOCK_STREAM over the
//     AF_UNIX protocol family. Address length is 2*108 = 216 bytes.
//
//   - \x32 : UNIX datagram : the forwarded connection uses SOCK_DGRAM over the
//     AF_UNIX protocol family. Address length is 2*108 = 216 bytes.
//
//
// Only the UNSPEC protocol byte (\x00) is mandatory to implement on the receiver.
// A receiver is not required to implement other ones, provided that it
// automatically falls back to the UNSPEC mode for the valid combinations above
// that it does not support.
//
// The 15th and 16th bytes is the address length in bytes in network endian order.
// It is used so that the receiver knows how many address bytes to skip even when
// it does not implement the presented protocol. Thus the length of the protocol
// header in bytes is always exactly 16 + this value. When a sender presents a
// LOCAL connection, it should not present any address so it sets this field to
// zero. Receivers MUST always consider this field to skip the appropriate number
// of bytes and must not assume zero is presented for LOCAL connections. When a
// receiver accepts an incoming connection showing an UNSPEC address family or
// protocol, it may or may not decide to log the address information if present.
//
// So the 16-byte version 2 header can be described this way :

typedef struct {
    uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t ver_cmd;  /* protocol version and command */
    uint8_t fam;      /* protocol family and address */
    uint16_t len;     /* number of following bytes part of the header */
} proxy_hdr_v2;

// Starting from the 17th byte, addresses are presented in network byte order.
// The address order is always the same :
//   - source layer 3 address in network byte order
//   - destination layer 3 address in network byte order
//   - source layer 4 address if any, in network byte order (port)
//   - destination layer 4 address if any, in network byte order (port)
//
// The address block may directly be sent from or received into the following
// union which makes it easy to cast from/to the relevant socket native structs
// depending on the address type :

typedef union {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ipv4_addr;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
         uint8_t  src_addr[16];
         uint8_t  dst_addr[16];
         uint16_t src_port;
         uint16_t dst_port;
    } ipv6_addr;
    struct {        /* for AF_UNIX sockets, len = 216 */
         uint8_t src_addr[108];
         uint8_t dst_addr[108];
    } unix_addr;
} proxy_V2_addr;

// The sender must ensure that all the protocol header is sent at once. This block
// is always smaller than an MSS, so there is no reason for it to be segmented at
// the beginning of the connection. The receiver should also process the header
// at once. The receiver must not start to parse an address before the whole
// address block is received. The receiver must also reject incoming connections
// containing partial protocol headers.
//
// A receiver may be configured to support both version 1 and version 2 of the
// protocol. Identifying the protocol version is easy :
//
//     - if the incoming byte count is 16 or above and the 13 first bytes match
//       the protocol signature block followed by the protocol version 2 :
//
//            \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x02
//
//     - otherwise, if the incoming byte count is 8 or above, and the 5 first
//       characters match the US-ASCII representation of "PROXY" then the protocol
//       must be parsed as version 1 :
//
//            \x50\x52\x4F\x58\x59
//
//     - otherwise the protocol is not covered by this specification and the
//       connection must be dropped.
//
// If the length specified in the PROXY protocol header indicates that additional
// bytes are part of the header beyond the address information, a receiver may
// choose to skip over and ignore those bytes, or attempt to interpret those
// bytes.
//
// The information in those bytes will be arranged in Type-Length-Value (TLV
// vectors) in the following format.  The first byte is the Type of the vector.
// The second two bytes represent the length in bytes of the value (not included
// the Type and Length bytes), and following the length field is the number of
// bytes specified by the length.

const char *const PROXY_V1_CONNECTION_PREFACE = "\x50\x52\x4F\x58\x59";
const char *const PROXY_V2_CONNECTION_PREFACE = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x02";

const size_t PROXY_V2_CONNECTION_PREFACE_LEN = 16
;
#define MIN_V1_HDR_LEN 15
#define MIN_V2_HDR_LEN 16
#define MIN_HDR_LEN MIN_V1_HDR_LEN

typedef struct {
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[0];
} pp2_tlv;

// A receiver may choose to skip over and ignore the TLVs he is not interested in
// or he does not understand. Senders can generate the TLVs only for
// the information they choose to publish.
//
// The following types have already been registered for the <type> field :

#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30


// 2.2.1 PP2_TYPE_ALPN
//
// Application-Layer Protocol Negotiation (ALPN). It is a byte sequence defining
// the upper layer protocol in use over the connection. The most common use case
// will be to pass the exact copy of the ALPN extension of the Transport Layer
// Security (TLS) protocol as defined by RFC7301 [9].
//
//
// 2.2.2 PP2_TYPE_AUTHORITY
//
// Contains the host name value passed by the client, as an UTF8-encoded string.
// In case of TLS being used on the client connection, this is the exact copy of
// the "server_name" extension as defined by RFC3546 [10], section 3.1, often
// referred to as "SNI". There are probably other situations where an authority
// can be mentionned on a connection without TLS being involved at all.
//
//
// 2.2.3. PP2_TYPE_CRC32C
//
// The value of the type PP2_TYPE_CRC32C is a 32-bit number storing the CRC32c
// checksum of the PROXY protocol header.
//
// When the checksum is supported by the sender after constructing the header
// the sender MUST:
//
//  - initialize the checksum field to '0's.
//
//  - calculate the CRC32c checksum of the PROXY header as described in RFC4960,
//    Appendix B [8].
//
//  - put the resultant value into the checksum field, and leave the rest of
//    the bits unchanged.
//
// If the checksum is provided as part of the PROXY header and the checksum
// functionality is supported by the receiver, the receiver MUST:
//
//  - store the received CRC32c checksum value aside.
//
//  - replace the 32 bits of the checksum field in the received PROXY header with
//    all '0's and calculate a CRC32c checksum value of the whole PROXY header.
//
//  - verify that the calculated CRC32c checksum is the same as the received
//    CRC32c checksum. If it is not, the receiver MUST treat the TCP connection
//    providing the header as invalid.
//
// The default procedure for handling an invalid TCP connection is to abort it.
//
//
// 2.2.4. PP2_TYPE_NOOP
//
// The TLV of this type should be ignored when parsed. The value is zero or more
// bytes. Can be used for data padding or alignment. Note that it can be used
// to align only by 3 or more bytes because a TLV can not be smaller than that.
//
//
// 2.2.5. The PP2_TYPE_SSL type and subtypes
//
// For the type PP2_TYPE_SSL, the value is itself a defined like this :

typedef struct {
        uint8_t  client;
        uint32_t verify;
        pp2_tlv sub_tlv[0];
} pp2_tlv_ssl;

// The <verify> field will be zero if the client presented a certificate
// and it was successfully verified, and non-zero otherwise.
//
// The <client> field is made of a bit field from the following values,
// indicating which element is present :

#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

// Note, that each of these elements may lead to extra data being appended to
// this TLV using a second level of TLV encapsulation. It is thus possible to
// find multiple TLV values after this field. The total length of the pp2_tlv_ssl
// TLV will reflect this.
//
// The PP2_CLIENT_SSL flag indicates that the client connected over SSL/TLS. When
// this field is present, the US-ASCII string representation of the TLS version is
// appended at the end of the field in the TLV format using the type
// PP2_SUBTYPE_SSL_VERSION.
//
// PP2_CLIENT_CERT_CONN indicates that the client provided a certificate over the
// current connection. PP2_CLIENT_CERT_SESS indicates that the client provided a
// certificate at least once over the TLS session this connection belongs to.
//
// The second level TLV PP2_SUBTYPE_SSL_CIPHER provides the US-ASCII string name
// of the used cipher, for example "ECDHE-RSA-AES128-GCM-SHA256".
//
// The second level TLV PP2_SUBTYPE_SSL_SIG_ALG provides the US-ASCII string name
// of the algorithm used to sign the certificate presented by the frontend when
// the incoming connection was made over an SSL/TLS transport layer, for example
// "SHA256".
//
// The second level TLV PP2_SUBTYPE_SSL_KEY_ALG provides the US-ASCII string name
// of the algorithm used to generate the key of the certificate presented by the
// frontend when the incoming connection was made over an SSL/TLS transport layer,
// for example "RSA2048".
//
// In all cases, the string representation (in UTF8) of the Common Name field
// (OID: 2.5.4.3) of the client certificate's Distinguished Name, is appended
// using the TLV format and the type PP2_SUBTYPE_SSL_CN. E.g. "example.com".
//
//
// 2.2.6. The PP2_TYPE_NETNS type
//
// The type PP2_TYPE_NETNS defines the value as the US-ASCII string representation
// of the namespace's name.
//
//
// 2.2.7. Reserved type ranges
//
// The following range of 16 type values is reserved for application-specific
// data and will be never used by the PROXY Protocol. If you need more values
// consider extending the range with a type field in your TLVs.

#define PP2_TYPE_MIN_CUSTOM    0xE0
#define PP2_TYPE_MAX_CUSTOM    0xEF

// This range of 8 values is reserved for temporary experimental use by
// application developers and protocol designers. The values from the range will
// never be used by the PROXY protocol and should not be used by production
// functionality.

#define PP2_TYPE_MIN_EXPERIMENT 0xF0
#define PP2_TYPE_MAX_EXPERIMENT 0xF7

// The following range of 8 values is reserved for future use, potentially to
// extend the protocol with multibyte type values.

#define PP2_TYPE_MIN_FUTURE    0xF8
#define PP2_TYPE_MAX_FUTURE    0xFF

#endif /* ProxyProtocol_H_ */
