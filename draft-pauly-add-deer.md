---
title: "Discovery of Equivalent Encrypted Resolvers"
abbrev: DEER
docname: draft-pauly-add-deer-latest
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
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net
  -
    ins: P. McManus
    name: Patrick McManus
    org: Fastly
    email: mcmanus@ducksong.com
  -
    ins: T. Jensen
    name: Tommy Jensen
    org: Microsoft
    email: tojens@microsoft.com

--- abstract

This document defines Discovery of Equivalent Encrypted Resolvers (DEER), a mechanism for DNS
clients to use unencrypted DNS to discover a resolver's encrypted DNS configuration. It is
designed to be agnostic to different forms of DNS encryption for future flexibility. It
is also designed to ensure that the encrypted server connection is controlled
by the same party controlling the unencrypted transmission of the configuration.
Opportunistic encryption that does not provide that assurance is defined as an option for
clients willing to accept that risk.

--- middle

# Introduction

When DNS clients wish to use encrypted protocols such as DNS-over-TLS (DoT) {{!RFC7858}}
or DNS-over-HTTPS (DoH) {{!RFC8484}}, they require additional information beyond the IP
address of the DNS server, such as the resolver's hostname. However, it is common for DNS
clients to only learn a resolver's IP address during configuration. Such mechanisms include
network provisioning protocols like DHCP and IPv6 Router Advertisements, as well as manual
configuration.

This document addresses encrypted DNS resolver discovery with two goals in mind: enable
discovery when only an IP address is known, and allow clients to confirm that the encrypted
resolver they connect to is the same entity as the known resolver that did not use encryption.

For DNS servers that do not support encryption, their encrypted connection configuration
can be requested by a new special use domain name (SUDN). For DNS servers that do support
encryption, this configuration can be requested based on a query for the encrypted server's name.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

DEER:
: Discovery of Equivalent Encrypted Resolvers. Refers to the mechanisms defined
in this document.

Encrypted Resolver:
: A DNS resolver using any encrypted DNS transport. This includes currently defined
mechanisms such as DoH and DoT as well as future mechanisms.

Equivalent Encrypted Resolver:
: An Encrypted Resolver which is considered to provide answers equivalent to a given 
resolver. This equivalency can be authenticated with PKI.

Unencrypted Resolver:
: A DNS resolver using TCP or UDP port 53.

# Discovery Mechanism

DNS resolvers can advertise one or more Equivalent Encrypted Resolvers that offer
equivalent services over encrypted channels and are controlled by the same entity.

When a client discovers Equivalent Encrypted Resolvers, it learns information such
as the supported protocols, ports, and server name to use in certificate validation.
This information is provided in a Service Binding (SVCB) records for DNS Servers,
defined by {{!I-D.schwartz-svcb-dns}}.

The following is an example of an SVCB record describing a DoH server:

~~~
_dns.example.net  7200  IN SVCB 1 . (
     alpn=h2 dohpath=/dns-query{?dns} ipv4hint=x.y.z.w )
~~~

The following is an example of an SVCB record describing a DoT server:

~~~
_dns.example.net  7200  IN SVCB 1 dot.example.net (
     alpn=dot port=8530 ipv4hint=x.y.z.w )
~~~

This document defines two ways clients can send queries for DNS server SVCB records:

1. Using a special use domain name to discover DNS server SVCB records associated
with the recursive resolver that is receiving the query {{bootstrapping}}.

2. Using the name of a known encrypted DNS server to query for alternate encrypted
DNS protocols supported by the server {{encrypted}}.

This document focuses on discovering DoH and DoT Equivalent Encrypted Resolvers.
Other protocols can also use the format defined by {{!I-D.schwartz-svcb-dns}}. However, if
any protocol does not involve some form of certificate validation, new validation mechanisms
will need to be defined to be equivalent to {{bootstrapping}}.

## Unencrypted Resolvers Advertising Equivalent Encrypted Resolvers {#bootstrapping}

When a DNS client is configured with an Unencrypted Resolver IP address, it SHOULD query
the resolver for SVCB records for "dns://resolver.arpa" before making other queries.
Specifically, the client issues a query for `_dns.resolver.arpa` with the SVCB
resource record type (64) {{I-D.ietf-dnsop-svcb-https}}.

If the recursive resolver that receives this query has one or more Equivalent Encrypted Resolvers,
it will return the corresponding SVCB records. When responding to these special queries
for "dns://resolver.arpa", the SVCB records SHOULD contain at least one "ipv4hint" and/or "ipv6hint"
keys. These address hints indicate the address on which the corresponding Encrypted Resolver
can be reached and avoid requiring an additional DNS lookup for the A and AAAA records of the
Encrypted Resolver name.

If multiple Equivalent Encrypted Resolvers are available, using one or more encrypted DNS protocols,
the resolver deployment can indicate a preference using the priority fields in each SVCB record {{I-D.ietf-dnsop-svcb-https}}.

In order to be considered an authenticated Equivalent Encrypted Resolver, the TLS certificate presented by the
Encrypted Resolver MUST contain both the domain name (from the SVCB answer) and the IP address of its
equivalent Unencrypted Resolver within the SubjectAlternativeName certificate field.
The client MUST check the SubjectAlternativeName field for both the Unencrypted Resolver's IP address
and the advertised name of the Equivalent Encrypted Resolver. If the certificate can be validated, the client
SHOULD use the discovered Equivalent Encrypted Resolver for any cases in which it would have otherwise
used the Unencrypted Resolver. If the Equivalent Encrypted Resolver has a different IP address than the
Unencrypted Resolver and the TLS certificate does not cover the Unencrypted Resolver address, the client
MUST NOT use the discovered Encrypted Resolver. Additionally, the client SHOULD suppress any
further queries for Equivalent Encrypted Resolvers using this Unencrypted Resolver for the length of time
indicated by the SVCB record's Time to Live (TTL).

If the Equivalent Encrypted Resolver and the Unencrypted Resolver share an IP address, clients MAY
choose to opportunistically use the Encrypted Resolver even without this certificate check ({{opportunistic}}).

## Opportunistic Discovery from Unencrypted Resolvers {#opportunistic}

There are situations where authenticated discovery of encrypted DNS configuration over
unencrypted DNS is not possible. This includes unencrypted resolvers on non-public IP
addresses whose identity cannot be confirmed using TLS certificates.

Clients who wish to attempt opportunistic DNS encryption MUST try authenticated
discovery first if the Unencrypted Resolver in use has a public IP address. If that
fails or the Unencrypted Resolver does not have a public IP address, the client MAY
attempt opportunistic encryption as defined in Section 4.1 of {{!RFC7858}} to the same
IP address without validating the resolver identity.

A client MAY opportunistically try using information from an SVCB record for
"dns://resolver.arpa" (as described in {{bootstrapping}}) as long as the IP address of
the Encrypted Resolver is not different than the IP address of the Unencrypted Resolver.
If the IP addresses for the Encrypted and Unencrypted Resolvers are not the same,
the client MUST NOT use the Encrypted Resolver opportunistically.

## Encrypted Resolvers Advertising Equivalent Encrypted Resolvers {#encrypted}

A DNS client may want to discover other DNS encryption transports supported by a known
Encrypted Resolver. This can be accomplished by sending the SVCB query using the known
name of the resolver.

This query can be issued to the known Encrypted Resolver itself, or to any other resolver.
Unlike the case of bootstrapping from an Unencrypted Resolver ({{bootstrapping}}), these
records SHOULD be available in the public DNS.

For example, if the client already knows about a DoT server `resolver.example.com`,
it can issue an SVCB query for `_dns.resolver.example.com` to discover if there are
other encrypted DNS protocols available. In the following example, the SVCB answers
indicate that `resolver.example.com` supports both DoH and DoT, and that the DoH
server indicates a higher priority than the DoT server.

~~~
_dns.resolver.example.com  7200  IN SVCB 1 . (
     alpn=h2 dohpath=/dns-query{?dns} )
_dns.resolver.example.com  7200  IN SVCB 2 . (
     alpn=dot )
~~~

Often, the various supported encrypted DNS protocols will be accessible using the same
hostname. In the example above, both DoH and DoT use the name `resolver.example.com`
for their TLS certficates. If a deployment uses a different hostname for one protocol,
but still wants clients to treat the DNS servers as equivalent, the TLS certificates MUST
include both names in the SubjectAlternativeName fields. Note that this name verification
is not related to the DNS resolver that provided the SVCB answer.

An example where discovering and Equivalent Encrypted Resolver for a known Encrypted Resolver
would be useful is when a client has a DoT configuration for `foo.resolver.example.com`,
but is on a network that blocks DoT traffic. The client can still send a query to some other accessible
resolver (either the local network resolver, or an accessible DoH server) to discover if there is an
equivalent DoH server for `foo.resolver.example.com`.

# Deployment Considerations

## Dropped Records

Because DEER relies on unencrypted DNS to acquire encrypted DNS configuration, on-path
attackers can prevent successful discovery by dropping SVCB packets. Clients should be
aware that it is not possible to distinguish between resolvers not supporting DEER and
DEER being actively blocked by an attacker.

## Forwarders

If a caching forwarder consults multiple resolvers, it may be possible for it to cache
records for the resolver.arpa SUDN for multiple resolvers. This may result in clients
using DEER to acquire Equivalent Encrypted Resolvers for resolver Foo and receiving
SVCB records for resolvers Foo and Bar. 

A client will successfully reject unintended connections because the authenticated
discovery will fail or, in the case of local addresses, because these records are not
used for opportunistic encryption. Clients who attempt opportunistic encryption to
addresses discovered through SVCB queries run the risk of connecting to the wrong server
in this scenario.

To prevent unnecessary traffic by clients to the wrong resolvers, DNS caching resolvers
SHOULD NOT cache results for the resolver.arpa SUDN other than their own Equivalent
Encrypted Resolvers.

## Certificate Management

Resolver owners will need to list valid referring IP addresses in their TLS certificates.
This may pose challenges for resolvers with a large number of referring IP addresses.

# Security Considerations

While the IP address of the Unencrypted Resolver is often provisioned over insecure mechanisms,
it can also be provisioned securely, such as via manual configuration, a VPN, or on a network with
protections like RA guard {{?RFC6105}}. An attacker might try to direct Encrypted DNS traffic to itself
by causing the client to think that a discovered Equivalent Encrypted Resolver uses a different IP
address from the Unencrypted Resolver. Such an Encrypted Resolver might have a valid certificate,
but be operated by an attacker that is trying to observe or modify user queries without the knowledge
of the client or network.

If the IP address of an Equivalent Encrypted Resolver differs from that of an Unencrypted Resolver, clients
MUST validate that the IP address of the Unencrypted Resolver is covered by the SubjectAlternativeName
of the Encrypted Resolver's TLS certificate ({{bootstrapping}}).

Opportunistic use of Encrypted Resolvers MUST be limited to cases where the Unencrypted Resolver
and Equivalent Encrypted Resolver have the same IP address ({{opportunistic}}).

# IANA Considerations {#iana}

## Special Use Domain Name "resolver.arpa"

This document calls for the creation of the "resolver.arpa" SUDN. This will allow resolvers to respond to
queries directed at themselves rather than a specific domain name. While this document uses "resolver.arpa"
to return SVCB records indicating equivalent encrypted capability, the name is generic enough to allow 
future reuse for other purposes where the resolver wishes to provide information about itself to the client.

--- back

# Rationale for using SVCB records {#rationale}

This mechanism uses SVCB/HTTPS resource records {{!I-D.ietf-dnsop-svcb-https}} to communicate that a given
domain designates a particular Equivalent Encrypted Resolver for clients to use in place of an Unencrypted
Resolver (using a SUDN) or another Encrypted Resolver (using its domain name).

There are various other proposals for how to provide similar functionality. There are several reasons that this
mechanism has chosen SVCB records:

- Discovering encrypted resolver using DNS records keeps client logic for DNS self-contained and allows a DNS
resolver operator to define which resolver names and IP addresses are related to one another.

- Using DNS records also does not rely on bootstrapping with higher-level application operations
(such as {{?I-D.schinazi-httpbis-doh-preference-hints}}).

- SVCB records are extensible and allow definition of parameter keys. This makes them a superior mechanism
for extensibility, as compared to approaches such as overloading TXT records. The same keys can be used for
discovering Equivalent Encrypted Resolvers of different transport types as well as those advertised by Unencrypted
Resolvers or another Encrypted Resolver.

- Clients and servers that are interested in privacy of names will already need to support SVCB records in order
to use Encrypted TLS Client Hello {{!I-D.ietf-tls-esni}}. Without encrypting names in TLS, the value of encrypting
DNS is reduced, so pairing the solutions provides the largest benefit.

- Clients that support SVCB will generally send out three queries when accessing web content on a dual-stack
network: A, AAAA, and HTTPS queries. Discovering an Equivalent Encrypted Resolver as part of one of these queries,
without having to add yet another query, minimizes the total number of queries clients send. While {{?RFC5507}}
recommends adding new RRTypes for new functionality, SVCB provides an extension mechanism that simplifies
client behavior.
