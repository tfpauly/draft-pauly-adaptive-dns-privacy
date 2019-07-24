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

--- abstract

This document defines an architecture that allows client hosts to dynamically
discover trusted resolvers that offer encrypted DNS services, and use them
in an adaptive way that improves privacy while co-existing with locally
provisioned resolvers. These trusted resolvers can be used directly whenever
a trusted association is established between a domain name and the resolver.
These resolvers also provide the ability to proxy encrypted queries, thus
obfuscating the identity of the client requesting resolution.

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

- A new DNS RRTYPE that indicates a trusted resolver associated with a name ({{rrtype}})

- A trusted resolver configuration that defines protocols and keys supported by a resolver ({{configuration}})

- An extension to DoH that allows queries to be obfuscated ({{obfuscation}})

- Client behavior rules for how to resolve names using trusted resolvers ({{client}})

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

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

# Client Behavior {#client}

## Hostname Resolution

## Discovering Trusted Resolvers {#discovery}

### Verifying Obfuscation Support  {#obfuscation-support}

### Mapping Domain Authority  {#domain-authority}

# Trusted Resolver Configuration {#configuration}

# Associated Trusted Resolver Records {#rrtype}

# Obfuscated Hostname Resolution in DoH {#obfuscation}

# Security Considerations

# IANA Considerations

# Acknowledgments
