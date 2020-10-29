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
encryption, this configuration can be requested based on a query for their own domain name.

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
equivalent services over encrypted channels and are controlled by the same entity 
as itself. To do this, a resolver returns one or more SVCB records for "dns://resolver.arpa"
with "ipv4hint" and/or "ipv6hint" set to a valid IP address and at least one of the the encrypted
resolver name keys set to a value used by the associated encrypted DNS transport. These
values are discussed in {{encryption-types}}.

The TLS certificate used with the resolver name MUST have the IP addresses for each of its DNS
endpoints within the SubjectAlternativeName field to allow the client to support authenticated
discovery.

## Authenticated Discovery from Unencrypted Resolvers {#bootstrapping}

When a DNS client is configured with an Unencrypted Resolver IP address, it SHOULD query
the resolver for SVCB records for "dns://resolver.arpa" before making other queries.

A DNS client MUST validate the Equivalent Encrypted Resolver and the Unencrypted Resolver that advertised it are
related, the client MUST check the SubjectAlternativeName field of the Equivalent Encrypted Resolver's
TLS certificate for the Unencrypted Resolver's IP address and the advertised IP address for the
Equivalent Encrypted Resolver. If both are present, the discovered Equivalent Encrypted Resolver MUST
be used whenever the Unencrypted Resolver would have been used. Otherwise, the client MUST NOT use the
discovered resolver and SHOULD suppress queries for Equivalent Encrypted Resolvers against
this resolver for the TTL of the negative or invalid response and continue to use the original resolver.

### Rationale for Validating Both Resolver Addresses

It is imperative that DNS clients require the IP addresses of both the Unencrypted Resolver
and the Equivalent Encrypted Resolver to be present in the TLS certificate.

If either IP address is not verified, an attacker can craft an SVCB record that will send the client
to a valid Encrypted Resolver that has no relationship with the Unencrypted Resolver.

### Encrypted Resolver SVCB Key Names {#encryption-types}

This document defines SVCB keys for discovering DoH and DoT Equivalent Encrypted Resolvers.
Future versions or other documents may define additional keys for discovery of resolvers
using other encrypted transports.

#### SVCB Records for Equivalent Encrypted Resolvers using DoH

The following example shows an Equivalent Encrypted Resolver using DoH, as returned by a query
for an SVCB record for "dns://resolver.arpa":

~~~
   _dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
                        ipv4hint=x.y.z.w
                        dohuri=https://doh.example.net/dns-query )
~~~

#### SVCB Records for Equivalent Encrypted Resolvers using DoT

The following example shows an Equivalent Encrypted Resolver using DoT, as returned by a query
for an SVCB record for "dns://resolver.arpa":

~~~
   _dns.resolver.arpa  7200  IN SVCB 1 dot.example.net (
                        ipv4hint=x.y.z.w
                        dothostname=dot.example.net )
~~~

## Opportunistic Discovery from Unencrypted Resolvers

There are situations where authenticated discovery of encrypted DNS configuration over
unencrypted DNS is not possible. This includes unencrypted resolvers on non-public IP
addresses whose identity cannot be confirmed using PKI.

Clients who wish to attempt opportunistic DNS encryption MUST try authenticated
discovery first if the Unencrypted Resolver in use has a public IP address. If that
fails or the Unencrypted Resolver does not have a public IP address, the client MAY
attempt opportunistic encryption as defined in Section 4.1 of {{!RFC7858}} to the same
IP address without validating the resolver identity.

### Opportunistic Discovery Cannot Change IP Addresses

Opportunistic discovery of DNS encryption MUST NOT identify a different IP address from
the Unencrypted Resolver's IP address. This is why there are no mechanisms defined for
Unencrypted Resolvers to advertise a different IP address unless it can be authenticated.

The reasoning behind this is to ensure the threat model for opportunistic encryption is
not weaker than simply continuing to use unencrypted DNS. If the IP address of the
Unencrypted Resolver was acquired by the DNS client securely such as by manual configuration,
allowing on-path attackers an opportunity to change the destination IP address for an
encrypted connection would worsen the security of the client. 


## Encrypted Resolvers advertising Equivalent Encrypted Resolvers

A DNS client may want to discover other DNS encryption transports supported by a given
Encrypted Resolver. This can be accomplished by using the same mechanism but sending an SVCB
query to the name of the Encrypted Resolver instead of the resolver.arpa SUDN.

This enables a resolver to modify its answer to match the name being queried. It also
enables resolvers to recursively answer the query if it is for a name it is not authoritative
for. An example where this would be useful is when a client has DoH and DoT configuration
for foo.resolver.example.com but only DoH configuration for bar.resolver.example.com. If DoH is
being blocked on the current network connection, a client can ask foo.resolver.example.com over
DoT for the DoT configuration for bar.resolver.example.com.

This differs from {{bootstrapping}} in that a trusted connection has already been
established. SVCB records containing Equivalent Encrypted Resolver configuration MUST NOT be
used if they were retrieved over an opportunistic encrypted DNS connection.

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

## Advertising cohosted Equivalent Encrypted Resolvers

Resolvers who serve more than one encrypted transport on the same IP address MAY return
these configurations together in a single SVCB record. For example, this record defines
a DoH and DoT server equivalent to the address the query was sent to:

~~~
   _dns.resolver.arpa  7200  IN SVCB 1 dns.example.net (
                        ipv4hint=x.y.z.w
                        dothostname=dns.example.net
                        dohuri=https://dns.example.net/dns-query )
~~~

Resolver administrators should be mindful of the implications of combining resolver
definitions into a single record, such as the shared TTL.

# Considerations

Resolver owners will need to list valid referring IP addresses in their TLS certificates.
This may pose challenges for resolvers with a large number of referring IP addresses.

# IANA Considerations {#iana}

## DNS Service Parameters

This document adds two parameters to the "Service Binding (SVCB) Parameter" registry.
The allocation request is 32768 and 32769, taken from the First Come First Served range.

### DoH URI Template

If present, this parameter indicates the URI template of a DoH server that is designated
as equivalent to the resolver providing the record. This is a string encoded as UTF-8 characters.

Name:
: dohuri

SvcParamKey:
: 32768

Meaning:
: URI template for an equivalent DoH server

Reference:
: This document.

### DoT Hostname

If present, this parameter indicates the hostname of a DoT server that is designated
as equivalent to the resolver providing the record. This is a string encoded as UTF-8 characters.

Name:
: dothostname

SvcParamKey:
: 32769

Meaning:
: Hostname for an equivalent DoT server

Reference:
: This document.

## Special Use Domain Name "resolver.arpa"

This document calls for the creation of the "resolver.arpa" SUDN. This will allow resolvers to respond to
queries directed at themselves rather than a specific domain name. While this document uses "resolver.arpa"
to return SVCB records indicating equivalent encrypted capability, the name is generic enough to allow 
future reuse for other purposes where the resolver wishes to provide information about itself to the client.

--- back

# Acknowledgments

Pending initial draft feedback.

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
