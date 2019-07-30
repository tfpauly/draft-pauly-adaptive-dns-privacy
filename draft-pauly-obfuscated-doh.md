---
title: "Obfuscated DNS Over HTTPS"
abbrev: Obfuscated DoH
docname: draft-pauly-obfuscated-doh-latest
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

--- abstract

This document describes an extension to DNS Over HTTPS (DoH) that allows Obfuscation
of client addresses via proxying.

--- middle

# Introduction

[TODO] Describe Obfuscated DoH

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

Obfuscation Proxy:
: A resolution server that proxies encrypted client DNS queries to another resolution server that
will be able to decrypt the query (the Obfuscation Target).

Obfuscation Target:
: A resolution server that receives encrypted client DNS queries via an Obfuscation Proxy.

# Protocol Details

Unlike direct resolution, obfuscated hostname resolution involves three parties:

1. The Client, which generates queries.
2. The Obfuscation Proxy, which is a resolution server that receives encrypted queries from the client
and passes them on to another resolution server.
3. The Obfuscation Target, which is a resolution server that receives proxied queries from the client
via the Obfuscation Proxy.

[TODO] Describe how to proxy (probably like HTTP proxying)

[TODO] Describe how to pack in client symmetric key

# Keying Material

# Client Behavior

# Obfuscation Proxy Behavior {#proxy}

# Obfuscation Target Behavior {#target}


# Security Considerations

# IANA Considerations

# Acknowledgments
