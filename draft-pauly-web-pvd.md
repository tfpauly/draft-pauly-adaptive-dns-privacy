---
title: Web Provisioning Domains
abbrev: QUIC Datagrams
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

informative:
  RFC2119:
  RFC8174:

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
private, or encrypted resolvers. This provides more granularity, but increases the burden on
the user.

3. Only use locally configured DNS servers, opportunistically using encrypted DNS to the
local server when available. This provides little benefit over not using encrypted DNS at all.

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

# Protocol

Define the protocol.

# Client Behavior

Web PvDs

# Security Considerations

Make it secure!

# IANA Considerations

Consider IANA.

# Acknowledgments

Thanks!
