---
title: "Adaptive DNS: Improving Privacy of Name Resolution"
abbrev: ADNS Privacy
docname: draft-pauly-adaptive-dns-privacy-latest
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
    
informative:
    RRTYPE:
      title: Associated Trusted Resolver Records
      authors:
        -
          T. Pauly
    OBFUSCATION:
      title: Obfuscated DNS Over HTTPS
      authors:
        -
          T. Pauly

--- abstract

This document defines an architecture that allows client hosts to dynamically
discover authoritative resolvers that offer encrypted DNS services, and use them
in an adaptive way that improves privacy while co-existing with locally
provisioned resolvers. These resolvers can be used directly when
looking up names for which they are authoritative. These resolvers also provide the ability
to proxy encrypted queries, thus obfuscating the identity of the client requesting resolution.

--- middle

# Introduction

When client hosts need to resolve names into addresses in order to establish networking connections,
they traditionally use by default the DNS resolver that is provisioned by the local router, or by
a tunneling server such as a VPN.

However, privacy-sensitive client hosts often would prefer to use a encrypted DNS service other
than the one locally provisioned in order to prevent interception or modification by untrusted parties along
the network path and centralized profiling by a single local resolver. Protocols that can improve the privacy
stance of a client when using DNS or creating TLS connections include DNS-over-TLS {{!RFC7858}},
DNS-over-HTTPS {{!RFC8484}}, and encrypted Server Name Indication (ENSI) {{!I-D.ietf-tls-esni}}.

There are several concerns around a client host using such privacy-enhancing mechanisms
for generic system traffic. A remote service that provides encrypted DNS may not provide
correct answers for locally available resources, or private resources (such as domains only
accessible over a private network). A remote service may also itself be untrusted from a
privacy perspective: while encryption will prevent on-path observers from seeing hostnames,
the client host needs to trust the encrypted DNS service to not store or misuse queries made
to it.

Client systems are left with choosing between one of the following stances:

1. Send all application DNS queries to a particular encrypted DNS service, which requires establishing
user trust of the service. This can lead to resolution failures for local or private enterprise domains.

2. Allow the user or another entity to configure local policy for which domains to send to local,
private, or encrypted resolvers. This provides more granularity, but increases user burden.

3. Only use locally-provisioned resolvers, and opportunistically use encrypted DNS to these resolvers
when possible. (Clients may learn of encrypted transport support by actively probing such
resolvers.) This provides marginal benefit over not using encrypted DNS at all, especially if clients
have no means of authenticating or trusting local resolvers.

This document defines an architecture that allows clients to improve the privacy of their
DNS queries without requiring user intervention, and allowing coexistence with local, private,
and enterprise resolver.

This architecture is composed of several mechanisms:

- A DNS RRTYPE that indicates an authoritative DoH resolver associated with a name ({{RRTYPE}})

- An extension to DoH that allows queries to be obfuscated ({{OBFUSCATION}})

- A DoH resolver configuration that defines protocols and keys supported by a resolver ({{configuration}})

- Client behavior rules for how to resolve names using a combination of authoritative DoH resolvers, obfuscated queries, and local resollvers ({{client}})

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

Adaptive DNS:
: Adaptive DNS is a technique to provide an encrypted transport for DNS queries that can
be sent directly to an Authoritative DoH Server, use Obfuscated DoH to hide the client
IP address, or use Direct Resolvers when required or appropriate.

Authoritative DoH Server:
: A DNS resolver that provides connectivity over HTTPS (DoH) that is known to be authoritative
for a given domain.

Direct Resolver:
: A DNS resolver using any transport that is provisioned directly by a local router or a VPN.

Exclusive Direct Resolver:
: A Direct Resolver that requires the client to use it exclusively for a given set of domains, such
as private domains managed by a VPN. This status is governed by local system policy.

Obfuscated DoH:
: A technique that uses multiple DoH servers to proxy queries in a way that obfuscates
the client's IP address.

Obfuscation Proxy:
: A resolution server that proxies encrypted client DNS queries to another resolution server that
will be able to decrypt the query (the Obfuscation Target).

Obfuscation Target:
: A resolution server that receives encrypted client DNS queries via an Obfuscation Proxy.

Privacy-Sensitive Connections:
: Connections made by clients that are explicitly Privacy-Sensitive are treated differently
from connections made for generic system behavior, such as non-user-initiated maintenance
connections. This distinction is only relevant on the client host, and does not get communicated
to other network entities. Certain applications, such as browsers, can choose to treat
all connections as privacy-sensitive.

# Client Behavior {#client}

Adaptive DNS allows client systems and applications to improve the privacy
of their DNS queries and connections both by requiring confidentiality via encryption
and by limiting the ability to correlate client IP addresses with query contents.
Specifically, the goal for client queries is to achieve the following properties:

- Eavesdroppers on the local network or elsewhere on the path will not be able to
read the names being queried by the client or the answers being returned
by the resolver.
- Only an authoritative DNS resolver that is associated with the deployment that is also
hosting content will be able to read both the client IP address and queried names for
Privacy-Sensitive Connections.
- Clients will be able to comply with policies required by VPNs and local networks that
are authoritative for private domains.

The algorithm for determining how to resolve a given name in a manner that satisfies
these properties is described in {{resolution-algorithm}}.

## Discovering Authoritative DoH Servers {#authoritative-discovery}

All direct (non-obfuscated) queries for names in privacy-sensitive connections MUST be sent to a
server that both provides encryption and is known to be authoritative for the domain.

Clients dynamically build and maintain a set of known Authoritative DoH Servers. The information
that is required to be associated with each server is:

- The URI Template of the DoH server
- The public key of the DoH server used for proxied obfuscated queries
- A list of domains for which the DoH server is authoritative

This information can be retrieved from several different sources. The primary source
for discovering Authoritative DoH Server configurations is the NS2 DNS Record
{{RRTYPE}}. This record provides the URI Template of the server and the public
obfuscation key for a specific domain.

When a client resolves a name (based on the order in {{resolution-algorithm}}) is SHOULD
issue a query for the NS2 record for any name that does not fall within known Authoritative
DoH Server's configuration. The client MAY also issue queries for the NS2 record for
more specific names to discover further Authoritative DoH Servers.

In order to bootstrap discovery of Authoritative DoH Servers, client systems SHOULD
have some saved list of at least two names that they use consistently to perform
NS2 record queries on the Direct Resolvers configured by the local network. Since
these queries are likely not private, they SHOULD NOT be associated with user
action or contain user-identifying content. Rather, the expection is that all client
systems of the same version and configuration would issue the same bootstrapping
queries when joining a network for the first time when the list of Authoritative
DoH Servers is empty.

### Whitelisting Authoritative DoH Servers  {#whitelisting}

Prior to using an Authoritative DoH Server for direct name queries on privacy-sensitive
connections, clients MUST whitelist the server.

The requirements for whitelisting are:

- Support for acting as an Obfuscation Proxy. Each Authoritative DoH Server is
expected to support acting as a proxy for Obfuscation. A client MUST issue at
least one query that is proxied through the server before sending direct queries
to the server.
- Support for acting as an Obfuscation Target. Each Authoritative DoH Server is
expected to support acting as a target for Obfuscation. A client MUST issue at
least one query that is targetd at the server through a proxy before sending direct queries
to the server.
- Signature/secondary cert by a trusted auditors. [TODO]

Clients MAY further choose to restrict the whitelist by other local policy. For example,
a client system can have a list of trusted resolver configurations, and it can limit
the whitelist of Authoritative DoH Servers to configurations that match this list.

## Discovering Local Resolvers {#local-discovery}

## Obfuscated Resolution

## Hostname Resolution Algorithm {#resolution-algorithm}

When establishing a secure connection to a certain hostname, clients need
to first determine which resolver configuration ought to be used for DNS resolution.
Given a specific hostname, and assuming that no other PvD or interface selection
requirement has been specified, the order of preference for which resolver to use
SHOULD be:

1. An Exclusive Direct Resolver, such as a resolver provisioned by a VPN,
domain rules that include the hostname being resolved. If the resolution
fails, the connection will fail.

2. A Direct Resolver, such as a local router, with domain rules that is known to be
authoritative for the domain containing the hostname. If the resolution fails,
the connection will try the next resolver configuration based on this list.

3. The most specific Authoritative DoH Server that has been whitelisted ({{whitelisting}}) for the domain
containing the hostname, i.e., the DoH server which is authoritative for the longest
matching prefix of the hostname. For example, given two Authoritative DoH Servers, one for
foo.example.com and another example.com, clients connecting to bar.foo.example.com
should use the former. If the resolution fails, the connection will try an obfuscated
query.

4. Obfuscated queries using multiple DoH Servers ({{OBFUSCATION}}). If this resolution fails,
Privacy-Sensitive Connections will fail. All other connections will use the last resort,
the default Direct Resolvers.

5. The default Direct Resolver, generally the resolver provisioned by the local router,
is used as the last resort for any connection that is not explicitly Privacy-Sensitive.

# Server Requirements {#server}

## DNS Over HTTPS Server

### Obfuscated DoH Proxy

### Obfuscated DoH Target

### Keying Material

## Advertising DoH Resolvers

## Associating Configuration {#configuration}

# Local Resolver Deployment Considerations

# Security Considerations

# IANA Considerations

# Acknowledgments
