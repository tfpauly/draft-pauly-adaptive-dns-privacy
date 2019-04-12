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

Introduce the protocol.

Provisioning Domains (PvDs) are defined as consistent sets of network configuration information {{!RFC7556}}.
This information includes configuration for how a client host should issue DNS queries and
route its traffic. Traditionally, a PvD is defined by a local network element (such as a router) or
by a VPN server. Routers can provide multiple PvDs, as defined in {{!I-D.ietf-intarea-provisioning-domains}}.

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
