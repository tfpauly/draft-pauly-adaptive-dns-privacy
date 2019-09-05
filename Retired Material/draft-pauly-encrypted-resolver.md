---
title: "Designated Encrypted Resolver Records"
abbrev: Designated Encrypted Resolver Records
docname: draft-pauly-encrypted-resolver
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
    ins: P. McManus
    name: Patrick McManus
    org: Fastly
    email: mcmanus@ducksong.com

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

This document defines a DNS resource record, DOHNS, that identifies
a designated name server that provides DNS Over HTTPS (DoH)
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

Discovering DNS servers that provide access over DoH can
also be used directly by clients. These servers can be specifically designated
as the correct resolvers to use for a given zone. Adaptive DNS ({{ADNS}}) defines an
algorithm that clients can use to improve their privacy stance by using
multiple DoH servers for resolution, and only resolving with a server directly
when that server is specifically designated for the zone that is being resolved.

This document defines a new RR, DOHNS, to indicate the location of an designated
DNS server that is accessible over DoH, along with information necessary
for clients to use the server.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Specifying DoH Servers in SVCB Records

{{!I-D.nygren-httpbis-httpssvc}} defines the SVCB record, along with a set of parameters
that can be associated with a service described in such a record.

This document defines two new keys to be added to the Service Binding (SVCB) Parameter Registry.

## DoH URI Template Parameter

If present, this parameters indicates the URI template of a DoH server that is designated
for use with the name being resolved. This is a string encoded as UTF-8 characters.

Name:
: dohuri

SvcParamKey:
: 4

Meaning:
: URI template for a designated DoH server

Reference:
: This document.

## Obfuscated DoH Public Key Parameter

If present, this key/value pair contains the public key to use when encrypting obfuscated messages that will be targeted at a DoH server. The format of the key is defined in {{OBFUSCATION}}.

Name:
: odohkey

SvcParamKey:
: 5

Meaning:
: Public key for use in Obfuscated DoH

Reference:
: This document.

# Security Considerations

All DOHNS resource records MUST be signed with DNSSEC, by being part
of a RRset that is covered by an RRSIG RR {{!RFC4034}}.

# IANA Considerations

This document defines a new RRTYPE in accordance with {{!RFC6895}}.
Please add the the following entry to the data type range of the Resource
Record (RR) TYPEs registry:

| TYPE | Meaning         | Reference      |
|:------------|:-----------------------|:---------------------|:------------|
| DOHNS     | Designated Encrypted Name Server | (This document) |

# Acknowledgments

Thanks to Erik Nygren for his input on this work ({{?I-D.nygren-httpbis-httpssvc}}).
