---
title: Web Provisioning Domains
abbrev: Web PvD
docname: draft-pauly-web-pvd-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: E. Kinnear
    name: Eric Kinnear
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: ekinnear@apple.com
  -
    ins: C. Wood
    name: Chris Wood
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

--- abstract

This document defines a mechanism for web services, such as HTTP servers
and Content Delivery Networks, to provide Provisioning Domain information
to client hosts. This information includes policies for using encrypted DNS
services, encrypted SNI keys for use in TLS, and protocol capabilities supported
by the web services.

--- middle

# Introduction

Provisioning Domains (PvDs) are defined as consistent sets of network configuration information {{!RFC7556}}.
This information includes configuration for how a client host should issue DNS queries and
route its traffic. Traditionally, a PvD is defined by a local network element (such as a router) or
by a VPN server. Routers can provide multiple PvDs, as defined in {{!I-D.ietf-intarea-provisioning-domains}}.

However, client hosts may want to use DNS configurations other than the one locally provisioned
to use encrypted DNS protocols to prevent interception or modification by untrusted parties along
the network path. Protocols that can improve the privacy stance of a client when using DNS or
creating TLS connections include DNS-over-TLS {{!RFC7858}}, DNS-over-HTTPS {{!RFC8484}},
and encrypted Server Name Indication (ENSI) {{!I-D.ietf-tls-esni}}.

There are several concerns around a client host using such privacy-enhancing mechanisms
for generic system traffic. A remote service that provides encrypted DNS may not provide
correct answers for locally available resources, or private resources (such as domains only
accessible over a private network). A remote service may also itself be untrusted from a
privacy perspective: while encryption will prevent on-path observers from seeing hostnames,
the client host needs to trust the encrypted DNS service to not store or misuse queries made
to it.

Client systems are left with choosing between one of the following stances:

1. Send all user DNS queries to a particular encrypted DNS service, which requires establishing
user trust of the service. This can lead to resolution failures for private enterprise domains.

2. Allow the user or another entity to configure local policy for which domains to send to local,
private, or encrypted resolvers. This provides more granularity, but increases user burden.

3. Only use locally configured DNS servers, opportunistically using encrypted DNS to local servers
when deemed available. (Clients may learn of encrypted transport support by actively probing such
resolvers.) This provides little benefit over not using encrypted DNS at all, especially if clients
have no means of authenticating local servers.

This document defines a protocol to allow servers to dynamically provision clients with
available PvD configurations to resolve and route traffic for which the servers are authoritative.
These PvDs, to contrast locally-defined PvDs, are referred to as "Web PvDs".

A Web PvD configuration that is signed by an authority for "example.com" can define
how to reach an encrypted DNS service that can resolve subdomains within "example.com",
provide access to keys to use for ESNI, and define how clients can optimally access hosts
for "example.com".

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document uses specific terms to identify the sets of configuration information
provisioned by network entities and used by clients.

PvD:
: A Provisioning Domain is a consistent set of network configuration information
as defined in {{!RFC7556}}.

Direct PvD:
: A Direct PvD is any defined set of PvD information made known to a client
via a provisioning protocol that provides physical or virtual or network access.
Examples include local routers (such as through DHCP or IPv6 Router Advertisements),
or VPN configurations.

Web PvD:
: A Web PvD is any set of PvD information fetched indirectly by a client that
specifies access to a set of servers based on domains.

Web PvD Configuration:
: A Web PvD Configuration is a container of information that describes how a client
can access Web resources, such as DNS servers supporting encryption and
obfuscation, connection coalescing rules, supported protocols, and proxies.

Authoritative PvD:
: A PvD is authoritative for a specific domain when the information it contains
is signed and authenticated by a valid certificate for the the domain.

Exclusive PvD:
: A PvD is exclusive for a specific domain if it prohibits any other PvD from being used
for the domain. For example, a VPN may prohibit the use of any other PvD for accessing
a private domain. Only Direct PvDs can be exclusive. Web PvDs MUST NOT be used
exclusively.

Privacy-Sensitive Connections:
: Connections made by clients that are explicitly Privacy-Sensitive are treated differently
from connections made for generic system behavior, such as non-user-initiated maintenance
connections. This distinction is only relevant on the client host, and does not get communicated
to other network entities.

Adaptive DNS:
: Adaptive DNS is a technique to provide an encrypted transport for DNS queries that can either
be sent directly to a server, or use a server to proxy the query and obfuscate the client address.

Obfuscation Proxy:
: A resolution server that proxies encrypted client DNS queries to another resolution server that
will be able to decrypt the query (the Obfuscation Target).

Obfuscation Target:
: A resolution server that receives encrypted client DNS queries via an Obfuscation Proxy.

# Client Behavior

## Hostname Resolution

When establishing a secure connection to a certain hostname, clients need
to first determine which PvD ought to be used for DNS resolution and connection
establishment. Given a specific hostname, and assuming that no other PvD or
interface selection requirement has been specified, the order of preference for which
PvD to use SHOULD be:

1. An Exclusive Direct PvD, such as a VPN, with domain rules that is known
to be authoritative for the domain containing the hostname. If the resolution
fails, the connection will fail.

2. A Direct PvD, such as a local router, with domain rules that is known to be
authoritative for the domain containing the hostname. If the resolution fails,
the connection will try the next PvD based on this list.

3. The most specific Web PvD that has been whitelisted ({{whitelisting}}) for the domain
containing the hostname, i.e., the Web PvD which is authoritative for the longest
matching prefix of the hostname. For example, given two Web PvDs, one for
foo.example.com and another example.com, clients connecting to bar.foo.example.com
should use the former. If the resolution fails, the connection will try an obfuscated
query.

4. Obfuscated queries using multiple Web PvDs ({{obfuscation}}). If this resolution fails,
Privacy-Sensitive Connections will fail. All other connections will use the last resort,
the default Direct PvD.

5. The default Direct PvD, generally the local router, is used as the last resort for any
connection that is not explicitly Privacy-Sensitive.

Web PvD information MAY be used for resolving hostnames for connections
that will be insecure (such as HTTP requests in cleartext). However, since the
metadata and content of such requests is already visible to on-path observers,
securing only the DNS step does not add significant benefit.

## Whitelisting Web PvDs {#whitelisting}

Clients MUST NOT use Web PvDs for direct hostname resolution, or any other capability
advertised by the Web PvD Configuration, until that Web PvD has been whitelisted for a
domain. There are two prerequisites for whitelisting a Web PvD:

1. Validate that the Web PvD provides obfuscation support ({{obfuscation-support}}).
2. Validate that the Web PvD is authoritative for the domain ({{domain-authority}}).

### Obfuscation Support  {#obfuscation-support}

Obfuscation support ({{obfuscation}}) MUST be proved before any domains are whitelisted
for a Web PvD. This is done to ensure that Web PvD providers are willing to participate in
the network of Web PvDs that allow a client to protect its identity when resolving hostnames.

It is sufficient to use a given Web PvD once as an Obfuscation Proxy and once as an Obfuscation Target
in order to determine support. For example, PvD A can be whitelisted once it has been used
to pass through an obfuscated query to PvD B; and has also been used to receive a query that was
passed through another PvD with a target of PvD A.

Clients SHOULD continue to use a variety of Web PvDs, rotating in random order, for hostname resolution of
domains that do not have authoritative Web PvDs.

### Domain Authority  {#domain-authority}

Each Web PvD can be authoritative for many domains. Authority for domains may also
change between multiple Web PvDs over time, as the agreements between the PvD providers
and server hosts change.

Prior to resolving hostnames directly with a Web PvD, a client MUST determine that the
Web PvD is authoritative for the domain containing the hostname. This is done whenever
the client receives and validates a Web PvD Domain Signature ({{signature}}), which can
be delivered either as part of a Web PvD Configuration or in a DNS TXT record.

# Web PvD Configuration {#configuration}

A Web PvD Configuration is defined as a JavaScript Object Notation (JSON) object {{!RFC8259}}.

The following keys are defined at the top-level of the JSON structure:

- "name" (required, string): a name used to identify this Web PvD for display purposes.
- "resolution-servers" (required, array of strings): an array of IP addresses and ports that the Web PvD supports for direct
resolution ({{resolution}}) or as an Obfuscation Proxy or Target ({{obfuscation}}). TODO: define address/port scheme
- "resolution-protocol" (required, string): the resolution protocol supported by the resolution servers.
TODO: define protocol enum, starting with aDNS.
- "resolution-key" (required, data): a public key used to sign resolution queries sent
to a Web PvD either directly ({{resolution}}) or via obfuscation ({{obfuscation}}).
- "domain-signatures" (optional, array): an array of Web PvD Domain signatures, defining the
default set of domains for which this PvD is authoritative ({{signature}}).
- "proxies" (optional, dictionary): a dictionary in which keys are domains (or "*" for all domains)
and values are proxy configurations to apply. TODO, define format.
- "esni-key": TODO, define ENSI key format.
- "protocols": TODO, define if QUIC, etc, is supported.
- "racing": TODO, defined Happy Eyeballs configuration.

TODO: Should the entire JSON structure be signed, or is that assumed by the transport?

# Web PvD Domain Signature {#signature}

# Web PvD Hostname Resolution {#resolution}

Web PvD Hostname Resolution allows a client to perform hostname resolution using a
resolution server specified by a Web PvD.

Web PvDs can support multiple protocols and encryption schemes to transmit messages used
for hostname resolution. Any such protocol MUST be encrypted and authenticated; and MUST
be able to transmit standard DNS messages {{!RFC1035}}.

While clients SHOULD only use a given resolution server for resolution of hostnames for which
the Web PvD is authoritative, the server SHOULD perform generic recursive DNS lookups even
when it is not the owner of the domain.

All Web PvDs MUST at least support a resolution protocol that supports obfuscation ({{obfuscation}}),
which also may be used for direct resolution. The resolution servers specified in the Web PvD
configuration ({{configuration}}) are specifically ones that support this protocol. The default protocol
defined for this purpose is Adaptive DNS ({{adns}}).

## Adaptive DNS {#adns}

Adaptive DNS (aDNS) is a protocol that allows clients to use a single secure transport connection
to send both direct DNS queries to a server and encrypted DNS queries that are destined to another
DNS server, to be proxied through the directly connected server. The direct queries are used
for hostnames for which the server is known to be authoritative, while the obfuscated queries
are used for all other hostnames. Clients SHOULD use multiple aDNS connections to
different servers simultaneously or in quick succession to be able to distribute obfuscated queries.

The description of aDNS in this document refers to the use of TLS and TCP, but the protocol
can function more generally over any transport that provides an encrypted reliable byte stream for
the TLS functionality, or an unencrypted reliable byte stream for the TCP functionality.

aDNS clients establish TLS {{!RFC8446}} connections to a resolution server that supports aDNS.
All messages sent on this encrypted byte stream have the following format:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Message Type                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                             ...                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-format title="aDNS Message Format"}

The common fields of all aDNS messages are as follows:

Length:

: A 32-bit integer in network byte order specifying the length of the message in bytes.
This includes the length field itself.

Message Type:

: The type of aDNS message, represented as a 32-bit integer in network byte order.

Defined message types include:

~~~
| Value   | Type                |
|:--------|:--------------------|
| 0x1     | DIRECT_QUERY        |
| 0x2     | DIRECT_ANSWER       |
| 0x3     | PROXY_QUERY         |
| 0x4     | ENCRYPTED_QUERY     |
| 0x5     | ENCRYPTED_ANSWER    |
~~~
{: #adns-message-types title="aDNS Message Types"}


When a client begins any hostname resolution, it first generates a unique Query ID. This
is a random 32-bit value. This Query ID is used on requests and responses between the client
and the server.

DIRECT_QUERY messages are formatted as follows:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Type (0x1)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Query ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                         DNS Message                           ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-direct-query-format title="aDNS DIRECT_QUERY Message Format"}

Upon reception of a DIRECT_QUERY message, the server performs DNS resolution
as a recursive resolver, and replies with a DIRECT_ANSWER message. The Query
ID MUST match the ID passed in the DIRECT_QUERY message.

DIRECT_ANSWER messages are formatted as follows:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Type (0x2)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Query ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                         DNS Message                           ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-direct-answer-format title="aDNS DIRECT_ANSWER Message Format"}

## Obfuscated Hostname Resolution in Adaptive DNS {#obfuscation}

Unlike direct resolution, obfuscated hostname resolution involves three parties:

1. The Client, which generates queries.
2. The Obfuscation Proxy, which is a resolution server that receives encrypted queries from the client
and passes them on to another resolution server.
3. The Obfuscation Target, which is a resolution server that receives proxied queries from the client
via the Obfuscation Proxy.

Any query that may be proxied through a server, for the purposes of obfuscation, cannot
directly send its DNS message without encrypting it further. Such messages are encoded as
PROXY_QUERY and ENCRYPTED_QUERY messages. A client can send a PROXY_QUERY message
to the Obfuscation Proxy, which can in turn send a ENCRYPTED_QUERY to the Obfuscation Target.

Query IDs generated Clients are random values that only are exposed to the Obfuscation
Proxy. The Obfuscation Proxy MUST generate new Query ID values (Query ID Prime values)
to use for messages sent on to the Obfuscation Target. When the Obfuscation Target answers,
the Query ID is translated back into the original Query ID before being passed to the Client.
The result of this is that a Query ID is only ever exposed to two parties (the Client and
the Obfuscation Proxy, or the Obfuscation Proxy and the Obfuscation Target), and never the
entire resolution chain.

PROXY_QUERY messages are formatted as follows:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Type (0x3)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Query ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Target Port           |  IP Version   |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Target Address (32 or 128 bits)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~            Encrypted Message (Server Public Key)              ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-proxy-query-format title="aDNS PROXY_QUERY Message Format"}

The fields of the PROXY_QUERY message are as follows:

Target Port:

: The TCP port of the aDNS server to receive the proxied query.

IP Version:

: The IP version of the address in Target Address.

Target Address:

: The IP address of the aDNS server to receive the proxied query. This can be 32-bits
for an IPv4 address or 128-bits for an IPv6 address.

Encrypted Message:

: The encrypted message is encrypted with a resolution server's public key, and contains
two fields, the Client Symmetric Key and the DNS Message. The Client Symmetric Key
MUST be a freshly generated and random symmetric key for each ENCRYPTED_QUERY.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                     Client Symmetric Key                      ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                         DNS Message                           ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-encrypted-format title="aDNS PROXY_QUERY and ENCRYPTED_QUERY Encrypted Message Format"}

ENCRYPTED_QUERY messages are sent by the Obfuscation Proxy to the Obfuscation
Target, and are the same as PROXY_QUERY without any proxy address
or port fields. The Query ID MUST be different from the original Query ID, as described
in {{obfuscation}}. The Encrypted Message is the same as the one in the PROXY_QUERY
message.

Since ENCRYPTED_QUERY messages are already encrypted, they do not need to be sent
over a TLS connection, but can be sent directly over TCP between the Obfuscation
Proxy and Obfuscation Target.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Type (0x4)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Query ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~            Encrypted Message (Server Public Key)              ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-encrypted-query-format title="aDNS ENCRYPTED_QUERY Message Format"}

Whenever an Obfuscation Target receives a ENCRYPTED_QUERY message, it decrypts the Encrypted
Message using its private key, and extracts the client symmetric key and the DNS
Message. It then sends a ENCRYPTED_ANSWER back to the Obfuscation Proxy, which
has the following format:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Type (0x5)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Query ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~           Encrypted Message (Client Symmetric Key)            ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #adns-encrypted-answer-format title="aDNS ENCRYPTED_ANSWER Message Format"}

The Obfuscation Proxy will recieve this answer, translate the Query ID to the correct
value for the Client, and pass the message along in the TLS connection to the Client,
otherwise unmodified.

TODO: Describe error handling for rejecting messages.

TODO: Define key constraints, lengths, ciphers.

# Security Considerations

Make it secure!

TODO: Add padding requirements.

# IANA Considerations

Consider IANA.

# Acknowledgments

Thanks!
