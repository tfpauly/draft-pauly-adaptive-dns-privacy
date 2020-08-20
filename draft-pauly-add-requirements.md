---
title: "Adaptive DNS Discovery Requirements"
abbrev: ADD Requirements
docname: draft-pauly-add-requirements-latest
date:
category: info

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

This document describes several use cases for discovering DNS resolvers that support
encrypted transports, and discusses how solutions for these use cases can be designed
to use common mechanisms. It also considers the requirements for privacy and security
when designing resolver discovery mechanisms.

--- middle

# Introduction

Several protocols for protecting DNS traffic with encrypted transports have been defined,
such as DNS-over-TLS (DoT) {{?RFC7858}} and DNS-over-HTTPS (DoH) {{?RFC8484}}.
Encrypted DNS can provide many security and privacy benefits for network clients.

While it is possible for clients to hard-code encrypted DNS resolvers to use, dynamic
discovery and provisioning of encrypted resolvers can expand the usefulness and
applicability of encrypted DNS to many more use cases.

This document first describes several use cases for discovering DNS resolvers that support
encrypted transports ({{use-cases}}).

Next, it discusses how solutions for these use cases can be grouped and categorized to point
to the usefulness of common mechanisms ({{mechanisms}}).

Last, it considers the requirements for privacy and security when designing resolver discovery
mechanisms ({{priv-sec}}).

This document is designed to aid in discussion of the Adaptive DNS Discovery (ADD) working
group as defines mechanism requirements.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Use Cases {#use-cases}

This section describes various use cases for which it is possible to discover an encrypted
resolver. For each use case, the privacy and security benefits of adding encrypted resolution
are briefly described.

## Network-provisioned resolvers {#local-network}

DNS servers are often provisioned by a network as part of DHCP options {{?RFC2132}} or
IPv6 Router Advertisement (RA) options {{?RFC8106}}. These options describe one or more
DNS resolver IP addresses, to be used for traditional unencrypted DNS.

Using an encrypted resolver that is provisioned by the network can provide several
benefits that are not possible if only unencrypted DNS is used:

- Prevent other devices on the network from observing client DNS messages
- Verify that answers come from the selected DNS resolver
- Authenticate that the DNS resolver is the one provisioned by the network

Often, network-provisioned resolvers are forwarders running on a local router. The discovered
encrypted resolvers in these cases may either be local fowarders themselves, or an associated
resolver that is in the network (thus bypassing the router's DNS forwarder).

## Client-selected resolvers {#client-selected}

Client devices often allow a user or administrator to select a specific DNS resolver to use
on certain networks, or on all networks. Historically, this selection was specified only with an
IP address.

Discovering if the selected resolver supports encryption, along with the configuration for the
encrypted resolver, allows the client to "upgrade" connections to use encrypted DNS.
This can provide several benefits:

- Prevent devices along the network path to the selected resolver from observing client DNS messages
- Verify that answers come from the selected DNS resolver
- Authenticate that the DNS resolver is the one selected by the client

## VPN resolvers {#vpn}

Virtual Private Networks (VPNs) also can provision DNS resolvers. In addition to being able to use
DHCP or RAs, VPNs can provision DNS information in an explicit configuration message. For example,
IKEv2 can provision DNS servers using Configuration Attributes {{?RFC7296}}.

VPNs can also configure Split DNS rules to limit the use of the configured resolvers to specific domain
names {{?RFC8598}}.

Discovering an encrypted resolver that is provisioned by a VPN can provide the same benefits
as doing so for a local network, but applied to the private network. When using Split DNS, it becomes
possible to use a one encrypted resolver for private domains, and another for other domains.

## Encrypted resolvers for private names {#private-names}

Similar to how VPN DNS configurations can use Split DNS for private names, other network environments
can support resolution of private names. For example, an enterprise-managed Wi-Fi network might
be able to access both the Internet an a private intranet. In such a scenario, the private domains managed
by the enterprise might only be resolvable using a specific DNS resolver.

Discovering an encrypted resolver for private domains allows a client to perform Split DNS while maintaining
the benefits of encrypted DNS. For example, a client could use a client-selected encrypted resolver for most
domains, but use a different encrypted resolver for enterprise-private domains.

This has the privacy benefit of only exposing DNS queries to the enterprise that fall within a limited set of
domains, if there is a more preferred option for generic Internet traffic.

Using encrypted DNS for private names also opens up the possibility of doing private name resolution outside
of the content of a VPN or managed network. If the DNS resolver authenticates clients, it can offer its resolver
for private names on a publicly accessible server, while still limiting the visibility of the DNS traffic.

## Encrypted resolvers for local or home content {#local-content}

Accessing locally-hosted content can require the use of a specific resolver. For example, captive networks
or networks with walled-garden content like media on airplane Wi-Fi networks can rely on using a
resolver hosted on the local network.

In cases where a client is using an encrypted resolver provisioned by a network, and that encrypted resolver
is able to resolve names local content, this can fall into the use case described in {{local-network}}. However,
it might be necessary to discover a local encrypted resolver along with specific domains if:

- the network-provisioned encrypted resolver is not able to resolve local-only names, or
- the client has a more-preferred encrypted resolver for generic traffic, and would otherwise not be able to access local content

This case also include accessing content specific to a home network.

## Encrypted resolvers for content providers {#cdn-content}

Content Delivery Networks (CDNs), and content-providers more broadly, can also provide encrypted
DNS resolvers that can be used by clients over the public Internet. These resolvers can either allow
resolution of all public names (like normal recursive resolvers), or be designed to serve a subset of names
managed by the content provider (like an authoritative resolver). Using these resolvers can allow the
content provider to directly control how DNS answers are used for load balancing and address selection,
which could improve performance of connections to the content provider.

Using a content-provider's encrypted resolver can also provide several privacy and security benefits:

- Prevent devices along the network path to the content-provider's resolver from observing client DNS messages
- Verify that answers come from the entity that manages the domains being resolved
- Reduce the number of entities able to monitor the specific names accessed by a client to only the client
and the content provider, assuming that the content provider would already see the names upon a secure connection
later being made based on the DNS answers (e.g., in the TLS SNI extension)

# Discovery mechanisms {#mechanisms}

The use cases described in {{use-cases}} do not all necessarily require separate mechanisms.

Generally, the use cases can be summarized in two categories:

1. Resolver upgrade: Discover encrypted resolvers equivalent to (or associated with) unencrypted resolvers.
Examples include network-provisioned, client-selected, and VPN-configured resolvers.
2. Domain-specific resolvers: Discover encrypted resolvers applicable to a limited set of domains.
Examples include resolvers for enterprise or private names, local content, and CDN content.

Resolver upgrade mechanisms can either add new parameters to existing provisioning
mechanisms (adding necessary information to use DoT or DoH to options in DHCP, RAs, or IKEv2) or else provide a way
to communicate with a provisioned unencrypted DNS resolver and discover the equivalent or associated encrypted
DNS resolver.

Domain-specific resolver discovery mechanisms additionally need to provide some information about the
applicability and capabilities of encrypted resolvers. This information could either be provisioned,
or be discovered based on clients actively trying to access content.

# Privacy and security requirements {#priv-sec}

A primary goal of encrypted DNS is improving the privacy and security of DNS queries and answers in the presence
of malicious attackers. Such attackers are assumed to interfere with or otherwise impede DNS traffic and corresponding
discovery mechanisms. They may be on-path or off-path between the client and entities with which the client
communicates. These attackers can inject, tamper, or otherwise interfere with traffic as needed.
Given these capabilities, an attacker may have a variety of goals, including, though not limited to:

- Monitor and profile clients by observing unencrypted DNS traffic

- Modify unencrypted DNS traffic to filter or augment the user experience

- Block encrypted DNS

Clients cannot assume that their network does not have such an attacker unless given some means of authenticating or otherwise
trusting the communication with their DNS resolver.

Given this type of attacker, resolver discovery mechanisms must be designed carefully to not worsen a client's security or
privacy posture in such networks. In particular, attackers must not be able to:

- Redirect DNS traffic to themselves.

- Override or adversely influence client resolver selection by users or administrators.

- Cause clients to use a discovered resolver which has no authenticated delegation from a client-known entity.

- Influence automatic discovery mechanisms such that a client uses one or more resolvers that are not
otherwise involved with providing service to the client, such as: a network provider, a VPN server, a
content provider being accessed, or a server that the client has manually configured.

Beyond these requirements, standards describing resolver discovery mechanisms must not place any requirements
on clients to select particular resolvers over others.

## On opportunistic encryption

Opportunistic encrypted DNS, when the client cannot authenticate the entity that provides encrypted DNS, does
not meet the requirements laid out here for resolver discovery. While opportunistic encryption can provide some
benefits, specifically in reducing the ability for other entities to observe traffic, it is not a viable solution
against an on-path attacker.

Performing opportunistic encrypted DNS does not require specific discovery mechanisms. Section 4.1 of {{?RFC7858}}
already describes how to use DNS-over-TLS opportunistically.

## Handling exceptions and failures

Even with encrypted DNS resolver discovery in place, clients must be prepared to handle certain scenarios where encrypted DNS
cannot be used. In these scenarios, clients must consider if it is appropriate to fail open by sending the DNS queries without
encryption, fail closed by not doing so, or presenting a choice to a user or administrator. The exact behavior is a
local client policy decision.

Some networks that use Captive Portals will not allow any Internet connectivity until a client has interacted with the portal
{{?I-D.ietf-capport-architecture}}. If these networks do not use encrypted DNS for their own resolution, a client will need to perform
unencrypted DNS queries in order to get out of captivity. Many operating systems have specific client code responsible for detecting
and interacting with Captive Portals; these system components may be good candidates for failing open, since they do not generally
represent user traffic.

Other networks may not allow any use of encrypted DNS, or any use of encrypted DNS to resolvers other than a network-provisioned
resolver. Clients should not silently fail open in these cases, but if these networks are trusted by or administered by the user, the user
may want to specifically follow the network's DNS policy instead of what the client would do on an unknown or untrusted network.
