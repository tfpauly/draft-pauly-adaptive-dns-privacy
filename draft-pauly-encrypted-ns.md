---
title: "Encrypted Authoritative Resolver Records"
abbrev: Encrypted NS Records
docname: draft-pauly-encrypted-ns
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
    ins: C. Wood
    name: Chris Wood
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com
  -
    ins: E. Kinnear
    name: Eric Kinnear
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: ekinnear@apple.com
    
normative:
    ADNS:
      title: "Adaptive DNS: Improving Privacy of Name Resolution"
      authors:
        -
          T. Pauly
    OBFUSCATION:
      title: Obfuscated DNS Over HTTPS
      authors:
        -
          T. Pauly

--- abstract

This document defines a DNS resource record, NS2, that identifies
an authoritative name server that provides DNS Over HTTPS (DoH)
access to clients and recursive resolvers. The record also contains
associated data required to use the name server.

--- middle

# Introduction

DNS-over-HTTPS {{!RFC8484}} (DoH) provides an encrypted and multiplexed
mechanism for performing DNS queries. DoH provides a mechanism for
encryption, which can help provide some privacy and security benefits.

Communication between recursive resolvers and authoritative servers
is not generally peformed over encrypted channels, however, since the
location of authoritative servers in NS resource records (RRs) does not
indicate that these servers provide support of protocols like DoH.

Discovering authoritative DNS servers that provide access over DoH can
also be used directly by client hosts. Adaptive DNS ({{ADNS}}) defines an
algorithm that clients can use to improve their privacy stance by using
multiple DoH servers for resolution, and only resolving with a server directly
when that server is known to be authoritative for the domain that is being resolved.

This document defines a new RR, NS2, to indicate the location of an authoritative
DNS server that is accessible over DoH, along with information necessary
for clients to use the server.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# The NS2 Resource Record

The NS2 RR contains two pieces of information in its RDATA:

- The URI Template of the DoH server {{!RFC8484}}
- The public key of the DoH server used for proxied obfuscated queries {{OBFUSCATION}}

# Security Considerations

All NS2 resource records MUST be signed with DNSSEC, by being part
of a RRset that is covered by an RRSIG RR {{!RFC4034}}.

# IANA Considerations

This document defines a new RRTYPE in accordance with {{!RFC6895}}.
Please add the the following entry to the data type range of the Resource
Record (RR) TYPEs registry:

| TYPE | Meaning         | Reference      |
|:------------|:-----------------------|:---------------------|:------------|
| NS2     | Authoritative Encrypted Name Server | (This document) |

# Acknowledgments

Thanks to Erik Nygren for his input on this work ({{?I-D.nygren-httpbis-httpssvc}}).
