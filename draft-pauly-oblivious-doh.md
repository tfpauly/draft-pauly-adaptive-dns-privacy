---
title: "Oblivious HTTPS"
abbrev: Oblivious HTTPS
docname: draft-pauly-oblivious-doh-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: E. Kinnear
    name: Eric Kinnear
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: ekinnear@apple.com
  -
    ins: P. McManus
    name: Patrick McManus
    org: Fastly
    email: mcmanus@ducksong.com
  -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

--- abstract

This document describes a new HTTP method for relaying encrypted HTTP requests
and responses between a client and target server using a proxy. This method hides
client IP addresses via from the target server, and the HTTP message contents
from the proxy server. This method may be used for oblivious DNS Over HTTPS (DoH).
This improves privacy of DNS operations by not allowing any one server entity to
be aware of both the client IP address and the content of DNS queries and answers.

--- middle

# Introduction

DNS Over HTTPS (DoH) {{!RFC8484}} defines a mechanism to allow DNS messages to be
transmitted in encrypted HTTP messages. This provides improved confidentiality and authentication
for DNS interactions in various circumstances.

While DoH can prevent eavesdroppers from directly reading the contents of DNS exchanges, it does
not allow clients to send DNS queries and receive answers from servers without revealing
their local IP address, and thus information about the identity or location of the client.

Proposals such as Oblivious DNS ({{?I-D.annee-dprive-oblivious-dns}}) allow increased privacy
by not allowing any single DNS server to be aware of both the client IP address and the
message contents.

This document defines the RELAY method, which is designed for a proxy server to relay
encrypted HTTP request and response bodies between a client and designated target.
This allows HTTP messages to be sent from a client to a target without the latter
learning the IP address of the former.

This mechanism is intended to be used as one option for resolving privacy-sensitive content
in the broader context of Adaptive DNS {{!I-D.pauly-dprive-adaptive-dns-privacy}}.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

Oblivious Proxy:
: A server that proxies encrypted client DNS queries to a resolution server that
will be able to decrypt the query (the Oblivious Target). Oblivious DoH servers
can function as proxies, but other non-resolver proxy servers could also be used.

Oblivious Target:
: A resolution server that receives encrypted client DNS queries and
generates encrypted DNS responses transferred via an Oblivious Proxy.

# Deployment Requirements

Oblivious HTTP requires, at a minimum:

- Two DoH servers, where one can act as an Oblivious Proxy, and the other can act as an
Oblivious Target.
- Public keys for encrypting DNS queries that are passed from a client through a proxy
to a target ({{publickey}}). These keys guarantee that only the intended Oblivious Target
can decrypt client queries.
- Client ability to generate random {{!RFC4086}} one-time-use symmetric keys to encrypt DNS responses. These
symmetric keys ensure that only the client will be able to decrypt the response from the
Oblivious Target. They are only used once to prevent the Oblivious Target from tracking
clients based on keys.

The mechanism for discovering and provisioning the DoH URI Templates and public keys
is via parameters added to DNS resource records. The mechanism for discovering the public
key is described in {{keydiscovery}}. The mechanism for discovering a DoH URI Template is
described in {{!I-D.pauly-dprive-adaptive-dns-privacy}}.

# HTTP Exchange

Unlike direct resolution, oblivious hostname resolution over DoH involves three parties:

1. The Client, which generates queries.
2. The Oblivious Proxy, which is a resolution server that receives encrypted queries from the client
and passes them on to another resolution server.
3. The Oblivious Target, which is a resolution server that receives proxied queries from the client
via the Oblivious Proxy.

~~~
     --- [ Request encrypted with target public key ] -->
+---------+             +-----------+             +-----------+
| Client  +-------------> Oblivious +-------------> Oblivious |
|         <-------------+   Proxy   <-------------+  Target   |
+---------+             +-----------+             +-----------+
   <-- [ Response encrypted with client symmetric key ] ---
~~~
{: #fig-doh-exchange title="Obvlivious DoH Exchange"}

# RELAY Method

The RELAY method requests that the recipient forward the contents of the
HTTP request to the destination origin server identified by the request-target
and forward any response as a result. RELAY is similar to the CONNECT method
in that the intermediary proxy forwards information between client and target.
However, RELAY does not require the client to establish an end-to-end connection
to the target through the proxy, which allows the proxy to re-use an existing
connection between itself and the target server.

A client sending a RELAY request MUST send the authority form
of request-target (Section 5.3 of {{!RFC7230}}); i.e., the request-
target consists of only the host name and port number of the relay
destination, separated by a colon. For example,

    RELAY target.example.com:443 HTTP/1.1
    Host: target.example.com:443

When using HTTP/2 {{!H2=RFC7540}} or later, RELAY requests use HTTP pseudo-headers
with the following requirements:

*  The ":method" pseudo-header field is set to "RELAY".
*  The ":scheme" pseudo-header field MUST be set to "https".
*  The ":path" pseudo-header field is set to the path to which the RELAY message
   body should be sent.
*  The ":authority" pseudo-header field contains the host and port to
  connect to (equivalent to the authority-form of the request-target
  of RELAY requests (see {{!RFC7230}}, Section 5.3)).

A RELAY request that does not conform to these restrictions is malformed
(see {{!H2}}, Section 8.1.2.6).

## RELAY Request {#oblivious-request}

The following example shows how a client requests that an Oblivious Proxy, "proxy.example.net",
forwards an encrypted message to "target.example.net". The URI template for the Oblivious
Proxy is "https://dnsproxy.example.net/dns-query{?targethost,targetpath}". The URI template for
the Oblivious Target is "https://dnstarget.example.net/dns-query".

~~~
:method = RELAY
:scheme = https
:authority = proxy.example.net
:path = /dns-query
accept = application/oblivious-http-message
cache-control = no-cache, no-store
content-type = application/oblivious-http-message
content-length = 106

<Bytes containing the encrypted payload for an Oblivious DNS query>
~~~

The Oblivious Proxy then sends the following request on to the Oblivious Target:

~~~
:method = POST
:scheme = https
:authority = target.example.net
:path = /dns-query
accept = application/oblivious-http-message
cache-control = no-cache, no-store
content-type = application/oblivious-http-message
content-length = 106

<Bytes containing the encrypted payload for an Oblivious DNS query>
~~~

## RELAY Response {#oblivious-response}

The response to an Oblivious message is generated by the Oblivious Target.
The body of the response contains an HTTP message that is encrypted with the
client's symmetric key ({{encryption}}). All other aspects of the HTTP response
and error handling are inherited from the HTTP specification(s).

The following example shows a response that can be sent from an Oblivious Target
to a client via an Oblivious Proxy.

~~~
:status = 200
content-type = application/oblivious-http-message
content-length = 154

<Bytes containing the encrypted payload for an Oblivious DNS response>
~~~

# Public Key Discovery {#keydiscovery}

In order to use an HTTP server as an Oblivious Target, the client must know a public
key to use for encrypting its HTTP messages. This key can be discovered using the SVCB
or HTTPS record type ({{!I-D.ietf-dnsop-svcb-https}}) for a name owned by the server.

The Service Binding key name is "relaykey" ({{iana}}). If present, this key/value
pair contains the public key to use when encrypting Oblivious DoH messages
that will be targeted at a DoH server. The format of the key is defined in ({{publickey}}).

Clients MUST only use keys that were retrieved from records protected by DNSSEC {{!RFC4033}}
to encrypt messages to an Oblivious Target.

# Relay Public Key Format {#publickey}

An Oblivious DNS public key is a structure encoded, using TLS-style encoding {{!RFC8446}}, as follows:

~~~
struct {
   uint16 kem_id;
   uint16 kdf_id;
   uint16 aead_id;
   opaque public_key<1..2^16-1>;
} RelayKey;
~~~

It contains the information needed to encrypt a message under RelayKey.public_key
such that only the owner of the corresponding private key can decrypt the message. The
values for RelayKey.kem_id, RelayKey.kdf_id, and RelayKey.aead_id
are described in {{!I-D.irtf-cfrg-hpke}} Section 7. For convenience, let
Identifier(RelayKey) be defined as the SHA256 value of RelayKey serialized.

# Oblivious DoH Message Format {#encryption}

There are two types of Oblivious DoH messages: Queries (0x01) and Responses (0x02). Both
are encoded as follows:

~~~
struct {
   uint8  message_type;
   opaque key_id<0..2^16-1>;
   opaque encrypted_message<1..2^16-1>;
} RelayMessage;
~~~

RelayMessage.message_type = 0x01 for Query messages and
RelayMessage.message_type = 0x02 for Response messages.
RelayMessage.key_id contains the identifier of the corresponding RelayKey key.
RelayMessage.encrypted_message contains an encrypted message for the Oblivious Target
(for Query messages) or client (for Response messages). The following sections describe how
these message bodies are constructed.

## Oblivious Queries

Oblivious HTTP Query messages must carry the following information:

1. A symmetric key under which the HTTP response will be encrypted. The AEAD algorithm
used for the client's response key is the one associated with the server's public key.
2. A HTTP message which the client wishes to relay to the proxy.
3. Padding of arbitrary length which MUST contain all zeros.

The key and message are encoded using the following structure:

~~~
struct {
   opaque http_message<1..2^16-1>;
   opaque response_seed[32];
   opaque padding<0..2^16-1>;
} RelayQueryBody;
~~~

Let M be an HTTP message a client wishes to protect with Oblivious DoH. When sending an
Oblivious HTTP messages to an Oblivious Target with RelayKey key pk, a client does the following:

1. Generate a random response seed of length 32 octets according to the guidelines in {{!RFC4086}}.
2. Create an RelayQueryBody structure, carrying the message M, response_seed, and padding, to produce Q_plain.
3. Unmarshal pk.public_key to produce a public key pkR of type pk.kem_id.
4. Compute the encrypted message as Q_encrypted = encrypt_query_body(pkR, key_id, Q_plain).
key_id is defined as Identifier(pk).
5. Output a RelayMessage message Q where Q.message_type = 0x01,
Q.key_id carries Identifier(pk), and Q.encrypted_message = Q_encrypted.

The client then sends Q to the Oblivious Proxy according to {{oblivious-request}}.

~~~
def encrypt_query_body(pkR, key_id, Q_plain):
  enc, context = SetupBaseI(pkR, "odns-query")
  aad = 0x01 || key_id
  ct = context.Seal(aad, Q_plain)
  Q_encrypted = enc || ct
  return Q_encrypted
~~~

## Oblivious Responses

An Oblivious HTTP Response message carries the DNS response (http_message) along with padding.
This message is encrypted with the client's chosen response key.

~~~
struct {
   opaque http_message<1..2^16-1>;
   opaque padding<0..2^16-1>;
} RelayResponseBody;
~~~

Targets that receive a Query message Q decrypt and process it as follows:

1. Look up the RelayKey according to Q.key_id. If no such key exists,
the Target MAY discard the query. Otherwise, let skR be the private key
corresponding to this public key, or one chosen for trial decryption, and pk
be the corresponding RelayKey.
2. Compute Q_plain, error = decrypt_query_body(skR, Q.key_id, Q.encrypted_message).
3. If no error was returned, and Q_plain.padding is valid (all zeros), resolve
Q_plain.http_message as needed, yielding a DNS message M.
4. Create an RelayResponseBody structure, carrying the message M and padding,
to produce R_plain.
5. Compute akey, anonce = derive_keys(Q_plain). (See definition for
derive_keys below. Hash, Expand, Extract, Nn, and Nk are functions and parameters
bound to the target's HPKE public key.)
6. Compute R_encrypted = encrypt_response_body(R_plain, akey, anonce). (See definition
for encrypt_response_body below. The key_id field used for encryption is empty,
yielding 0x0000 as part of the AAD.)
7. Output a RelayMessage message R where R.message_type = 0x02,
R.key_id = nil, and R.encrypted_message = R_encrypted.

~~~
def derive_keys(Q_plain):
  context = Hash(Q_plain.http_message)
  key = Expand(Q_plain.response_seed, concat("ohttp key", context), Nk)
  nonce = Expand(Q_plain.response_seed, concat("ohttp nonce", context), Nn)
  return key, nonce
~~~

~~~
def decrypt_query_body(skR, key_id, Q_encrypted):
  enc || ct = Q_encrypted
  dec, context = SetupBaseR(skR, "ohttp-query")
  aad = 0x01 || key_id
  Q_plain, error = context.Open(aad, ct)
  return Q_plain, error
~~~

~~~
def encrypt_response_body(R_plain, akey, anonce):
  aad = 0x02 || 0x0000 // 0x0000 represents a 0-length KeyId
  R_encrypted = Seal(akey, anonce, aad, R_plain)
  return R_encrypted
~~~

The Target then sends R to the Proxy according to {{oblivious-response}}.

The Proxy forwards the message R without modification back to the client as
the HTTP response to the client's original HTTP request.

Once the client receives the response, it can use its known response_seed
to derive the decryption key and nonce, decrypt R.encrypted_message using
decrypt_response_body (defined below), and produce R_plain. Clients MUST
validate R_plain.padding (as all zeros) before using R_plain.http_message.

~~~
def decrypt_response_body(R_encrypted):
  aad = 0x02 || 0x0000
  R_plain = Open(response_key, 0^Nn, aad, R_encrypted)
  return R_plain
~~~

# Security Considerations

DISCLAIMER: this is a work in progress draft and has not yet seen significant security analysis.

Oblivious DoH aims to keep knowledge of the true query origin and its contents known to only
clients. In particular, it assumes a Dolev-Yao style attacker which can observe all client queries,
including those forwarded by oblivious proxies, and does not collude with target resolvers. (Indeed,
if a target colludes with the network attacker, then said attacker can learn the true query origin
and its contents.) Oblivious DoH aims to achieve the following confidentiality goals in the presence
of this attacker:

1. Queries and answers are known only to clients and targets in possession of the corresponding
response key and HPKE keying material. In particular, proxies know the origin and destination
of an oblivious query, yet do not know the plaintext query. Likewise, targets know only the oblivious
query origin, i.e., the proxy, and the plaintext query. Only the client knows both the plaintext
query contents and destination.
2. Target resolvers cannot link queries from the same client in the absence of unique per-client
keys.

Traffic analysis mitigations are outside the scope of this document. In particular, this document
does not recommend padding lengths for RelayQueryBody and RelayResponseBody messages.
Implementations SHOULD follow the guidance for choosing padding length in {{!RFC8467}}.

Oblivious DoH security does not depend on proxy and target indistinguishability. Specifically, an
on-path attacker could determine whether a connection a specific endpoint is used for oblivious or
direct DoH queries. However, this has no effect on confidentiality goals listed above.

## Denial of Service

Malicious clients (or proxies) may send bogus Oblivious DoH queries to targets as a Denial-of-Service
(DoS) attack. Target servers may throttle processing requests if such an event occurs.

Malicious targets or proxies may send bogus answers in response to Oblivious DoH queries. Response
decryption failure is a signal that either the proxy or target is misbehaving. Clients can choose to stop using
one or both of these servers in the event of such failure.

## General Proxy Services

Using DoH over anonymizing proxy services such as Tor would also achieve the desired goal of separating
query origins from their contents. However, there are several reasons why such systems are undesirable
in comparison Oblivious DoH:

1. Tor is also meant as a generic connection-level anonymity system, and thus seems overly complex for
the purpose of proxying individual DoH queries. In contrast, Oblivious DoH is a lightweight extension
to standard DoH that can be enabled as a default mode for users which need increased privacy.

2. As a one-hop proxy, Oblivious DoH encourages connection-less proxies to mitigate client query correlation
with few round-trips. In contrast, multi-hop systems such as Tor often run secure connections (TLS) end-to-end,
which means that DoH servers could track queries over the same connection. Using a fresh DoH connection
per query would incur a non-negligible penalty in connection setup time.

# IANA Considerations {#iana}

## Oblivious DoH Message Media Type

This document registers a new media type, "application/oblivious-http-message".

Type name: application

Subtype name: oblivious-http-message

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: This is a binary format, containing encrypted DNS
requests and responses, as defined in this document.

Security considerations: See this document. The content is an encrypted DNS
message, and not executable code.

Interoperability considerations: This document specifies format of
conforming messages and the interpretation thereof.

Published specification: This document.

Applications that use this media type: This media type is intended
to be used by clients wishing to hide their DNS queries when
using DNS over HTTPS.

Additional information: None

Person and email address to contact for further information: See
Authors' Addresses section

Intended usage: COMMON

Restrictions on usage: None

Author: IETF

Change controller: IETF

## Relay Public Key DNS Parameter

This document defines one new key to be added to the Service Binding (SVCB) Parameter Registry
{{!I-D.ietf-dnsop-svcb-https}}.
s
Name:
: relaykey

SvcParamKey:
: TBD

Meaning:
: Public key used to encrypt messages in Oblivious DoH

Reference:
: This document.

# Acknowledgments

This work is inspired by Oblivious DNS {{?I-D.annee-dprive-oblivious-dns}}. Thanks to all of the
authors of that document. Thanks to Frederic Jacobs, Elliot Briggs, Paul Schmitt, Brian Swander, and
Tommy Jensen for the feedback and input.
