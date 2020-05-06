---
title: "Adaptive DNS Resolver Discovery"
abbrev: ADNS Discovery
docname: draft-pauly-add-resolver-discovery-latest
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

--- abstract

This document defines a method for dynamically discovering resolvers that support
encrypted transports, and introduces the concept of a designating a resolver
to be used for a subset of client queries based on domain. This method is intended
to work both for locally-hosted resolvers and resolvers accessible over the broader
Internet.

--- middle

# Introduction

When clients need to resolve names into addresses in order to establish networking connections,
they traditionally use by default the DNS resolver that is provisioned
by the local network along with their IP address {{?RFC2132}} {{?RFC8106}}. Alternatively, they
can use a resolver indicated by a tunneling service such as a VPN.

However, privacy-sensitive clients might prefer to use an encrypted DNS service other
than the one locally provisioned in order to prevent interception,
profiling, or modification by entities other than the operator of the
name service for the name being resolved. Protocols that can improve the transport security
of a client when using DNS or creating TLS connections include DNS-over-TLS {{!RFC7858}},
DNS-over-HTTPS {{!RFC8484}}, and encrypted Server Name Indication (ESNI) {{!I-D.ietf-tls-esni}}.

This document defines a method for dynamically discovering resolvers that support
encrypted transports, and introduces the concept of a designating a resolver
to be used for a subset of client queries based on domain. This method is intended
to work both for locally-hosted resolvers and resolvers accessible over the broader
Internet.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document defines the following terms:

Companion DoH Server:
: A DNS resolver that provides connectivity over HTTPS (DoH) that is designated as 
equivalent to querying a given Direct Resolver.

Designated Resolver:
: A DNS resolver that is designated as a responsible resolver for a given domain or zone.

Direct Resolver:
: A DNS resolver using any transport that is provisioned directly by a local router or a VPN.

# Designated Resolvers

- Based on DNSSEC-signed SVCB record
- Based on confirmation of a trusted domain, listed in additional information
- Use IP hints for addresses

# Discovering Designated DoH Resolvers

Clients dynamically build and maintain a set of known Designated DoH Servers. The information
that is associated with each server is:

- The URI Template of the DoH server {{!RFC8484}}
- A list of domains for which the DoH server is designated

This information can be retrieved from several different sources. The primary source
for discovering Designated DoH Server configurations is from properties stored in a
SVCB (or a SVCB-conformant type like HTTPSSVC) DNS Record {{!I-D.nygren-dnsop-svcb-httpssvc}}.
This record provides the URI Template of a DoH server that is designated for a specific domain.
A specific domain may have more than one such record.

In order to designate a DoH server for a domain, a SVCB record can
contain the "dohuri" ({{iana}}). The value stored in the parameter
is a URI, which is the DoH URI template {{!RFC8484}}.

The following example shows a record containing a DoH URI, as returned by a query for
the HTTPSSVC variant of the SVCB record type on "example.com".

~~~
   example.com.      7200  IN HTTPSSVC 0 svc.example.net.
   svc.example.net.  7200  IN HTTPSSVC 2 svc1.example.net. (
									   dohuri=https://doh.example.net/dns-query
									   odohkey="..." )
~~~

Clients SHOULD NOT accept designations for effective top-level domains (eTLDs), such
as ".com".

# Explicit Discovery of Local Resolvers {#local-discovery}

If the local network provides configuration with an Explicit Provisioning Domain (PvD), as
defined by {{!I-D.ietf-intarea-provisioning-domains}}, clients can learn about domains
for which the local network's resolver is authoritative.

If an RA provided by the router on the network defines an Explicit PvD that has additional
information, and this additional information JSON dictionary contains the key "dohTemplate" ({{iana}}),
then the client SHOULD add this DoH server to its list of known DoH configurations. The
domains that the DoH server claims authority for are listed in the "dnsZones" key. Clients
MUST use an SVCB record from the locally-provisioned DoH server and validate
the answer with DNSSEC {{!RFC4033}} before creating a mapping from the domain to the server.
Once this has been validated, clients can use this server for resolution as described in
step 2.

See {{local-deployment}} for local deployment considerations.

# Discovery of DoH Capabilities for Direct Resolvers

Direct Resolvers can advertise a Companion DoH server that offers equivalent services and is controlled 
by the same entity. To do this, a DNS server MUST return an HTTPSSVC record for the "resolver.arpa"
domain with "dohip" set to a valid IP address and the "dohuri" key set to a valid DoH URI 
template as with the Designated DoH Server HTTPSSVC record. The TLS certificate used with the
DoH URI MUST have the IP addresses for each of its DNS endpoints, classic or DoH, within the 
SubjectAlternativeName field to allow the client to verify ownership.

If the client is configured to query a Direct Resolver, it MUST query that resolver for an SVCB record for the 
"resolver.arpa" domain. This SHOULD occur before making other queries to avoid leaking queries that could go over
DoH once the Companion DoH Server is discovered. If an SVCB record is returned, its "dohip" field designates an 
IP address the client can send DoH queries to in lieu of sending classic DNS queries to the Direct Resolver. The "dohuri" and "odohkey" fields contains the DoH URI similarly to the HTTPSSVC record for a Designated DoH Server. 

To validate the Companion DoH Server and the resolver that advertised it are related, the client MUST 
check the SubjectAlternativeName field of the Companion DoH Server's TLS certificate for the original 
resolver's IP address and the advertised IP address for the Companion DoH server. If both are present, the
discovered Companion DoH Server MUST be used whenever the original Direct Resolver would be used. Otherwise, 
the client SHOULD suppress queries for Companion DoH Servers against this resolver for the TTL of the negative 
or invalid response and continue to use the original Direct Resolver.

The following example shows a record containing a Companion DoH URI, as returned by a query for
the HTTPSSVC variant of the SVCB record type on the "resolver.arpa" domain.

~~~
   resolver.arpa  7200  IN HTTPSSVC 2 resolver.arpa (
                        dohip=x.y.z.w
                        dohuri=https://doh.example.net/dns-query )
~~~

A DNS resolver MAY return more than one HTTPSSVC record of this form to advertise multiple Companion 
DoH Servers that are valid as a replacement for itself. Any or all of these servers may have the same IP 
address as the DNS resolver itself. In this case, clients will only have one IP address to check for when 
verifying ownership of the Companion DoH server.

# Server Deployment Considerations

When servers designate DoH servers for their names, the specific deployment
model can impact the effective privacy and performance characteristics.

## Single Content Provider

If a name always resolves to server IP addresses that are hosted by a single
content provider, the name ought to designate a single DoH server. This
DoH server will be most optimal when it is designated by many or all names
that are hosted by the same content provider. This ensures that clients
can increase connection reuse to reduce latency in connection setup.

A DoH server that corresponds to the content provider that hosts content has an
opportunity to tune the responses provided to a client based on the location
inferred by the client IP address.

## Multiple Content Providers

Some hostnames may resolve to server IP addresses that are hosted by multiple
content providers. In such scenarios, the deployment may want to be able to
control the percentage of traffic that flows to each content provider.

In these scenarios, there can either be:

- multiple designated DoH servers that are advertised via SVCB DNS Records; or,

- a single designated DoH server that can be referenced by one or more SVCB DNS Records,
operated by a party that is aware of both content providers and can manage
splitting the traffic.

If a server deployment wants to easily control the split of traffic between different
content providers, it ought to use the latter model of using a single designated DoH server
that can better control which IP addresses are provided to clients. Otherwise, if a
client is aware of multiple DoH servers, it might use a single resolver exclusively,
which may lead to inconsistent behavior between clients that choose different resolvers.

## Avoid Narrow Deployments

Using designated DoH servers can improve the privacy of name resolution whenever
a DoH server is designated by many different names within one or more domains.
This limits the amount of information leaked to an attacker observing traffic between a
client and a DoH server: the attacker only learns that the client might be resolving
one of the many names for which the server is designated.

However, if a deployment designates a given DoH server for only one name, or a
very small set of names, then it becomes easier for an attacker to infer that a specific
name is being accessed by a client. For this reason, deployments are encouraged
to avoid deploying a DoH server that is only designated by a small number of names.
Clients can also choose to only whitelist DoH servers that are associated with
many names.

Beyond the benefits to privacy, having a larger number of names designate
a given DoH server improves the opportunity for DoH connection reuse, which
can improve the performance of name resolutions.

# Local Resolver Deployment Considerations {#local-deployment}

A key goal of Adaptive DNS is that clients will be able to use Designated DoH Servers
to improve the privacy of queries, without entirely bypassing local network authority and
policy. For example, if a client is attached to an enterprise Wi-Fi network that provides
access and resolution for private names not generally accessible on the Internet, such
names will only be usable when a local resolver is used.

In order to achieve this, a local network can advertise itself as authoritative for a domain,
allowing it to be used prior to external servers in the client resolution algorithm.

## Designating Local DoH Servers {#designating-local-servers}

If a local network wants to have clients send queries for a set of private domains to its own resolver,
it needs to define an explicit provisioning domain {{!I-D.ietf-intarea-provisioning-domains}}.
The PvD RA option SHOULD set the H-flag to indicate that Additional Information is available.
This Additional Information JSON object SHOULD include both the "dohTemplate" and "dnsZones"
keys to define the local DoH server and the domains over which it claims authority.

In order to validate that a local resolver is designated for a given zone, the client SHOULD issue
a SVCB record query for the names specified in the PvD information, using the DoH server specified
in the PvD information. If there is no SVCB record for a name that points to the DoH server that can be validated
using DNSSEC, the client SHOULD NOT automatically create a designation from the domain name to DoH server.
See specific use cases in {{local-use-cases}} for cases in which a local resolver may still be used.

## Local Use Cases {#local-use-cases}

The various use cases for selecting locally-provisioned resolvers require different approaches for
deployment and client resolution. The following list is not exhaustive, but provides guidance on how
these scenarios can be achieved using the Adaptive DNS algorithm.

### Accessing Local-Only Resolvable Content

Some names are not resolvable using generic DNS resolvers, but require using a DNS server that can
resolve private names. This is common in enterprise scenarios, in which an enterprise can have
a set of private names that it allows to be resolved when connected to a VPN or an enterprise-managed
Wi-Fi network. In this case, clients that do not use the locally-provisioned resolver will fail to resolve
private names.

In these scenarios, the local network SHOULD designate a local DoH server for the domains that are
locally resolvable. For example, an enterprise that owns "private.example.org" would advertise
"private.example.org" in its PvD information along with a DoH URI template. Clients could then
use that locally-configured resolver with names under "private.example.org" according to the rules in {{designating-local-servers}}.

In general, clients SHOULD only create designated DoH server associations when they can validate a SVCB
record using DNSSEC. However, some deployments of private names might not want to sign all
private names within a zone. There are thus a few possible deployment models:

- "private.example.org" does have a DNSSEC-signed SVCB record that points to the local DoH server.
The client requests the SVCB record for "private.example.org" using the local DoH server that is
specified in the PvD information, and from that point on uses the local DoH server for names under
"private.example.org".

- Instead of signing "private.example.org", the deployment provides a DNSSEC-signed SVCB record
for "example.org", thus steering all resolution under "example.org" to the local resolver.

- No DNSSEC-signed SVCB record designates the local server. In this case, clients have a hint that
the local network can serve names under "private.example.org", but do not have a way to validate
the designation. Clients can in this case try to resolve names using external servers (such
as via Oblivious DoH), and then MAY fall back to using locally-provisioned resolvers if the names do not
resolve externally. This approach has the risk of exposing private names to public resolvers,
which can be undesirable for certain enterprise deployments. Alternatively, if the client trusts
the local network based on specific policy configured on the client, it can choose to resolve these names
locally first. Note that this approach risks exposing names to a potentially malicious network that is
masquerading as an authority for private names if the network cannot be validated in some other manner.

Deployments SHOULD use the one of the first two approaches (signing their records) whenever possible;
the case of providing unsigned names is only described as a possibility for handling legacy enterprise
deployments. Clients SHOULD choose to ignore any locally designated names that are not
signed unless there is a specific policy configuration on the client.

### Accessing Locally Optimized Content

Other names may be resolvable both publicly and on the local resolver, but have more optimized
servers that are accessible only via the local network. For example, a Wi-Fi provider may provide
access to a cache of video content that provides lower latency than publicly-accessible caches.

Names that are hosted locally in this way SHOULD use a designation with a DNSSEC-signed SVCB
record for the name. If a client discovers that a local resolver is designated for a given name, the
client SHOULD prefer using connections to this locally-hosted content rather than names resolved
externally.

Note that having a DNSSEC-signed designation to the local resolver provides a clear indication
that the entity that manages a given name has an explicit relationship with the local network provider.

### Walled-Garden and Captive Network Deployments {#captive}

Some networks do not provide any access to the general Internet, but host local content that
clients can access. For example, a network on an airplane can give access to flight information
and in-flight media, but will not allow access to any external hosts or DNS servers. These
networks are often described as "walled-gardens".

Captive networks {{?I-D.ietf-capport-architecture}} are similar in that they block access to
external hosts, although they can provide generic access after some time.

If a walled-garden or captive network defines a PvD with additional information, it can
define zones for names that it hosts, such as "airplane.example.com". It can also provide a
locally-hosted encrypted DNS server.

However, if such a network does not support explicitly advertising local names,
clients that try to establish connections to DoH servers will experience connection failures.
In these cases, system traffic that is used for connecting to captive portals SHOULD
use local resolvers. In addition, clients MAY choose to fall back to using direct
resolution without any encryption if they determine that all connectivity is blocked otherwise.
Note that this comes with a risk of a network blocking connections in order to induce this
fallback behavior, so clients might want to inform users about this possible attack where
appropriate, or prefer to not fall back if there is a concern about leaking user data.

### Network-Based Filtering

Some networks currently rely on manipulating DNS name resolution in order to apply
content filtering rules to clients associated with the network. Using encrypted DNS resolvers
that are not participating in this filtering can bypass such enforcement. However, simply
blocking connections for filtering is indistinguishable from a malicious attack from
a client's perspective.

In order to indicate the presence of filtering requirements, a network deployment
can add the "requireDNSFiltering" and "dnsFilteredZones" keys to its PvD information.
The "dnsFilteredZones" entry can contain an array of strings, each of which is a domain
name that the network requires clients to resolve using the local resolver. If the array contains
the string ".", it indicates the network requires filtering for all domains. If "requireDNSFiltering"
is present with a boolean value of true, the network is indicating that it expects all client systems
to send the names indicated by "dnsFilteredZones" to the local resolver. If "requireDNSFiltering"
is not present or set to false, then the filtering service is considered to be optional for clients
that want to use it as a service to enforce desired policy.

Clients that receive indication of filtering requirements SHOULD NOT use any other
resolver for the filtered domains, but treat the network as claiming authority. However,
since this filtering cannot be authenticated, this behavior SHOULD NOT be done
silently without user consent.

Networks that try to interfere with connections to encrypted DNS resolvers without
indicating a requirement for filtering cannot be distinguished from misconfigurations
or network attacks. Clients MAY choose to avoid sending any user-initiated connections
on such networks to prevent malicious interception.

# Security Considerations

In order to avoid interception and modification of the information retrieved by clients
using Adaptive DNS, all exchanges between clients and servers are performed over encrypted
connections, e.g., TLS.

Malicious adversaries may block client connections to a DoH service as a
Denial-of-Service (DoS) measure. Clients which cannot connect to any proxy may, by local
policy, fall back to unencrypted DNS if this occurs.

# Privacy Considerations

Clients must be careful in determining to which DoH servers they send queries
directly without proxying. A malicious DoH server that can direct queries to itself
can track or profile client activity. In order to avoid the possibility of a spoofed SVCB
record designating a malicious DoH server for a name, clients MUST ensure that
such records validate using DNSSEC {{!RFC4033}}.

Even servers that are officially designated can risk leaking or logging information
about client lookups. Such risk can be mitigated by further restricting the list of
DoH servers that are whitelisted for direct use based on client policy.

An adversary able to see traffic on each path segment of a DoH query (e.g., from client to
proxy, proxy to target, and target to an authoritative DNS server) can link queries to specific
clients with high probability. Failure to observe traffic on any one of these path segments
makes this linkability increasingly difficult. For example, if an adversary can only
observe traffic between a client and proxy and egress traffic from a target, then it may
be difficult identify a specific client's query among the recursive queries generated by the target.

# IANA Considerations {#iana}

## DoH Template PvD Key

This document adds a key to the "Additional Information PvD Keys" registry {{!I-D.ietf-intarea-provisioning-domains}}.

| JSON key | Description         | Type      | Example      |
|:------------|:-----------------------|:---------------------|:------------|
| dohTemplate     | DoH URI Template {{!RFC8484}} | String | "https://dnsserver.example.net/dns-query{?dns}" |

## DNS Filtering PvD Keys

This document adds a key to the "Additional Information PvD Keys" registry {{!I-D.ietf-intarea-provisioning-domains}}.

| JSON key | Description         | Type      | Example      |
|:------------|:-----------------------|:---------------------|:------------|
| requireDNSFiltering    | A flag to indicate that the network requires filtering all DNS traffic using the provisioned resolver. | Boolean | true |
| dnsFilteredZones    | A list of DNS domains as strings that represent domains that can be filtered by the provisioned resolver. | Array of Strings | [ "." ] |

Any network that sets the "requireDNSFiltering" boolean to false but provides "dnsFilteredZones" advertises the optional
service of filtering on the provisioned network.

An "." in the "dnsFilteredZones" array represents a wildcard, which can be used to indicate that the network is requesting
to filter all names. Any more specific string represents a domain that requires filtering on the network.

## DoH URI Template DNS Parameter

If present, this parameters indicates the URI template of a DoH server that is designated
for use with the name being resolved. This is a string encoded as UTF-8 characters.

Name:
: dohuri

SvcParamKey:
: TBD

Meaning:
: URI template for a designated DoH server

Reference:
: This document.

# Acknowledgments

Thanks to Erik Nygren, Lorenzo Colitti, Tommy Jensen, Mikael Abrahamsson,
Ben Schwartz, Ask Hansen, Leif Hedstrom, Tim McCoy, Stuart Cheshire, Miguel Vega,
Joey Deng, Ted Lemon, and Elliot Briggs for their feedback and input on this document.
