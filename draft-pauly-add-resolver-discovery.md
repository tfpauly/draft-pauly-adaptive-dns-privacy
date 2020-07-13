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
  -
    ins: T. Jensen
    name: Tommy Jensen
    org: Microsoft
    email: tojens@microsoft.com

--- abstract

This document defines a method for dynamically discovering resolvers that support
encrypted transports, and introduces the concept of designating a resolver
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
of a client when using DNS or creating TLS connections include DNS-over-TLS (DoT) {{!RFC7858}},
DNS-over-HTTPS (DoH) {{!RFC8484}}, and Encrypted TLS Client Hellos {{!I-D.ietf-tls-esni}}.

This document defines a method for dynamically discovering resolvers that support
encrypted transports, and introduces the concept of designating a resolver
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

Direct Resolver:
: A DNS resolver using any transport, encrypted or unencrypted, that is provisioned directly by a local router or a VPN.

Designated Resolver:
: A DNS resolver that is designated as a responsible resolver for a given domain or zone. Designated resolvers use encrypted transports.

Companion DoH Server:
: A DNS resolver that provides connectivity over HTTPS (DoH) that is designated as 
equivalent to querying a particular Direct Resolver.

# Designated Resolvers

An encrypted DNS resolver, such as a DoH or DoT server, can be designated for use in resolving names within one or more zones. This means that clients can learn about an explicit mapping from a given domain or zone to one or more Designated Resolvers, and use that mapping to select the best resolver for a given query.

Designating a resolver MUST rely on agreement between the entity managing a zone (the Domain Owner) and the entity operating the resolver, such that clients can securely validate this designation. These entities can be one and the same, or a Domain Owner can choose to designate a third-party resolver to handle its traffic. Proof of this agreement asserts to clients that sending any query to the designated resolver exposes no more information than sending that query to the entity managing the corresponding zone.

As an example with only one entity, a company that runs many sites within "enterprise.example.com" can provide its own DoH resolver, "doh.enterprise.example.com", and designate only that resolver for all names that fall within "enterprise.example.com". This means that no other resolver would be designated for those names, and clients would only resolve names with the same entity that would service TLS connections.

As an example with several entities, the organization that operates sites within "example.org" may work with two different Content Delivery Networks (CDNs) to serve its sites. It might designate names under "example.com" to two different entities, "doh.cdn-a.net" and "doh.cdn-b.net". These are CDNs that have an existing relationship with the organization that runs "example.org", and have agreements with that organization about how data with information on names and users is handled.

There are several methods that can be used to discover and validate a resolver designation:

- Discovery using SVCB DNS records ({{svcb}}), and validation using DNSSEC
- Discovery using information in a provisioning domain (PvD) file from the Designated DoH Resolver ({{pvd}})
- Validation using a file hosted on a well-known HTTPS URI based on a zone apex ({{confirm-zone-apex}})
- Validation using TLS certificates to confirm of domain name ownership ({{confirm-cert-name}})

Note that clients MUST NOT accept designations for effective top-level domains (eTLDs), such as ".com".

## Designating with Service Binding DNS Records {#svcb}

The primary source for discovering Designated DoH Server configurations is from properties stored in a
SVCB DNS resource record, or a SVCB-conformant resource record type, like HTTPS {{!I-D.ietf-dnsop-svcb-https}}.
This record provides the URI Template of a DoH server that is designated for a specific domain.
A specific domain may have more than one such record.

The rationale for using SVCB records for recolver discovery is discussed in {{rationale}}.

In order to designate a DoH server for a domain, a SVCB record can
contain the "dohuri" ({{iana}}). The value stored in the parameter
is a URI, which is the DoH URI template {{!RFC8484}}.

The following example shows a record containing a DoH URI, as returned by a query for
the HTTPS variant of the SVCB record type on "foo.example.com".

~~~
   foo.example.com.  7200  IN HTTPS 1 . (
                           dohuri=https://doh.example.net/dns-query )
~~~

If this record is DNSSEC-signed {{!RFC4033}}, clients can immediately create a mapping that indicates the server (doh.example.net) as a Designated Resolver for the name in the SVCB record (foo.example.com).

Once a record that designated a DoH server has expired, the client SHOULD issue another SVCB/HTTPS query whenever issuing queries within the designated domain. This query SHOULD still be performed using the designated DoH server. If the response designates a different DoH server, the client should verify and use the new designation.

If this record is not DNSSEC-signed, clients MUST perform other validation to determine that the zone designation is permitted, as described in {{confirm-zone-apex}}.

## Additional Designation with PvD JSON {#pvd}

A provisioning domain (PvD) defines a coherent set of information that can be used to access a network and resolve names. Section 4.3 of {{!I-D.ietf-intarea-provisioning-domains}} defines a JSON dictionary format that can be fetched over HTTPS at the well-known URI "/.well-known/pvd".

Designated Resolvers that support DoH SHOULD provide a PvD JSON dictionary available at the well-known PvD URI with the path of the DoH server's URI template appended.

For example, the PvD JSON for the DoH server "https://doh.example.net/dns-query" would be available at "https://doh.example.net/.well-known/pvd/dns-query".

The key "dohTemplate" is defined within the JSON dictionary ({{iana}}) to point back to the DoH URI Template itself. This is used for confirming the DoH server when the PvD is discovered locally or during zone apex confirmation ({{confirm-zone-apex}}).

Names that are listed in the "dnsZones" key in the JSON dictionary indicate a set of zones that designate the resolver. These are the zones that are available to resolve through the associated DoH server. Note that this list does not need to be exhaustive, but is the set of common zones managed by the resolver that all clients should be aware of. Before using  DNS results for these names, clients MUST validate the designation either with a DNSSEC-signed SVCB record ({{svcb}}), or the confirmation methods described in {{confirm-zone-apex}} and {{confirm-cert-name}}. DNS queries for validating records SHOULD be sent to the DoH resolver. In order to optimize the validation of these domains, servers MAY use HTTP Server Push to deliver the signed SVCB answers prior to requests being made.

The "expires" key indicates a time after which the content of the PvD file is no longer valid. Clients SHOULD re-fetch PvD information if the expiration time has passed before using any designations that were based on the PvD content.

~~~
   {
	 "identifier": "doh.example.net.",
	 "dohTemplate": "https://doh.example.net/dns-query",
	 "dnsZones": ["example.com"],
	 "expires": "2020-08-23T06:00:00Z"
   }
~~~

## Confirmation of Designation with Zone Apex PvD {#confirm-zone-apex}

Designated DoH Resolvers that provide the PvD JSON described in {{pvd}} can also provide information to validate of zone's designation without DNSSEC.
In order to confirm the designation, the client requests a well-known HTTPS URI based on a zone apex name, and checks a PvD file to ensure that
it matches the DoH resolver. This ensures that a DoH resolver cannot claim a designation for a given zone without cooperation from the entity that owns
the certificate for the apex of that zone.

In order to enumerate the zone apex names that confirm designation in this manner, the DoH resolver's PvD JSON dictionary can contain
an array of strings, with the key "trustedNames". Clients can validate the resolver designation by checking a resource hosted by a
name indicated in "trustedNames". The client first issues an HTTP GET request by appending "/.well-known/pvd" to the trusted name,
using the "https" scheme. In order to validate the designation, the PvD JSON MUST contain a "dohTemplate" key pointing to the correct DoH
resolver. The client's query for the IP addresses of the trusted name MAY use the DoH resolver prior to fully validating the designation,
since the validation uses HTTPS to authenticate the designation.

Note that the names listed in "trustedNames" are only useful for confirming a designation that was indicated either by a non-DNSSEC-signed
SVCB designation ({{svcb}}), or an additional designation provided by the DoH resolver's PvD ({{pvd}}). A trusted name MUST be an exact match of
a designating name, or else a parent of a designating name.

If a name has more specific sub-domains that should not be allowed to designate a given DoH resolver, this method of confirmation MUST NOT be used.

As an example of this process, the JSON dictionary for the DoH server "https://doh.example.net/dns-query", which is retrieved from "https://doh.example.net/.well-known/pvd/dns-query", could contain the following contents:

~~~
   {
     "identifier": "doh.example.net.",
     "dohTemplate": "https://doh.example.net/dns-query",
     "dnsZones": ["example.com"],
     "trustedNames": ["example.com"],
     "expires": "2020-08-23T06:00:00Z"
   }
~~~

This indicates that "example.com" should be treated as a designated domain, and that it can be validated by checking with the "example.com" server rather than using DNSSEC.

In this example, the well-known URI used for validation is "https://example.com/.well-known/pvd". In order to trust the designation, this request must return valid JSON with the "dohTemplate" key matching the original DoH resolver. For example, this dictionary could contain the following contents:

~~~
   {
     "identifier": "example.com.",
     "dohTemplate": "https://doh.example.net/dns-query",
     "expires": "2020-08-23T06:00:00Z"
   }
~~~

A client MUST NOT trust a designation if the JSON content is not present, does not contain a "dohTemplate" key, or the value in the "dohTemplate" key does not match. The following result would not be acceptable for the example above:

~~~
   {
     "identifier": "example.com.",
     "dohTemplate": "https://not-the-doh-youre-looking-for.example.net/dns-query"
     "expires": "2020-08-23T06:00:00Z"
   }
~~~

Note that the domains listed in "trustedNames" may be broader than the zones that designate the resolver. In the following example, names under "foo.example.com" and "bar.example.com" designate the DoH server "https://doh.example.net/dns-query", and use the PvD JSON from "example.com" to validate the designation. However, the client would not designate the DoH server for all names under "example.com".

~~~
   {
     "identifier": "doh.example.net.",
     "dohTemplate": "https://doh.example.net/dns-query",
     "dnsZones": ["foo.example.com", "bar.example.com"],
     "trustedNames": ["example.com"],
     "expires": "2020-08-23T06:00:00Z"
   }
~~~

## Confirmation of Designation with TLS Certificates {#confirm-cert-name}

A DoH server designation can also be validated by checking the SubjectAlternativeName field in the DoH
server's own TLS certificate. When a client wants to confirm the validity of the 
designation in this situation, it can check the TLS certificate of the DoH server for the name of the domain 
which triggered the original designation query.

The following example shows an HTTPS variant of the SVCB record type for "foo.example.com". If this record was
received without DNSSEC, the client can confirm its validity by establishing a connection to "doh.example.net" 
and verifying the TLS certificate contains an exact match for the "foo.example.com" name. If the queried domain 
is not present in the TLS certificate of the designated DoH server, the client may confirm the validity by an 
alternate method such as zone apex confirmation ({{confirm-zone-apex}}) but MUST NOT use the record until otherwise validated.

~~~
   foo.example.com.  7200  IN HTTPS 1 . (
                           dohuri=https://doh.example.net/dns-query )
~~~

# Explicit Discovery of Local Resolvers {#local-discovery}

If the local network provides configuration with an Explicit Provisioning Domain (PvD), as
defined by {{!I-D.ietf-intarea-provisioning-domains}}, clients can learn about domains
for which the local network's resolver is authoritative. The keys for DoH resolvers described in {{pvd}} also allow this local PvD to be used for resolver discovery.

If an RA provided by the router on the network defines an Explicit PvD that has additional
information, and this additional information JSON dictionary contains the key "dohTemplate",
then the client SHOULD add this DoH server to its list of known DoH configurations. The
domains that the DoH server claims authority for are listed in the "dnsZones" key.

Local deployments that want to designate a resolver for a private name that is not easily
signed with DNSSEC MUST provide an alternate method of validating a designation, such as described
in {{confirm-zone-apex}} or {{confirm-cert-name}}.

# Discovery of DoH Capabilities for Direct Resolvers {#direct}

Direct Resolvers can advertise a Companion DoH server that offers equivalent services and is controlled 
by the same entity. To do this, a DNS server returns an SVCB record for "dns://resolver.arpa"
with "ipv4hint" and/or "ipv6hint" set to a valid IP address and the "dohuri" key set to a valid DoH URI 
template as with the Designated DoH Server SVCB record. The TLS certificate used with the
DoH URI MUST have the IP addresses for each of its DNS endpoints, classic or DoH, within the 
SubjectAlternativeName field to allow the client to verify ownership.

Once a client is configured to query a Direct Resolver, it SHOULD query the resolver for SVCB records 
for "dns://resolver.arpa" before making other queries. This will help the client avoid leaking queries that 
could go over DoH once the Companion DoH Server is discovered. If an SVCB record is returned, its "dohip" field 
designates an IP address the client can send DoH queries to in lieu of sending classic DNS queries to the Direct 
Resolver. The "dohuri" field contains the DoH URI similarly to the SVCB record for a Designated 
DoH Server. 

To validate the Companion DoH Server and the resolver that advertised it are related, the client MUST 
check the SubjectAlternativeName field of the Companion DoH Server's TLS certificate for the original 
resolver's IP address and the advertised IP address for the Companion DoH server. If both are present, the
discovered Companion DoH Server MUST be used whenever the original Direct Resolver would be used. Otherwise, 
the client SHOULD suppress queries for Companion DoH Servers against this resolver for the TTL of the negative 
or invalid response and continue to use the original Direct Resolver.

The following example shows a record containing a Companion DoH URI, as returned by a query for an SVCB record 
for "dns://resolver.arpa":

~~~
   _dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
                        ipv4hint=x.y.z.w
                        dohuri=https://doh.example.net/dns-query )
~~~

A DNS resolver MAY return more than one SVCB record of this form to advertise multiple Companion 
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
Clients can also choose to only allow DoH servers that are associated with
many names.

Beyond the benefits to privacy, having a larger number of names designate
a given DoH server improves the opportunity for DoH connection reuse, which
can improve the performance of name resolutions.

# Security Considerations

In order to avoid interception and modification of the information sent between clients
and Designated Resolvers, all exchanges between clients and servers are performed over encrypted
connections, e.g., TLS.

Malicious adversaries may block client connections to a Designated Resolver as a
Denial-of-Service (DoS) measure. Clients which cannot connect these resolvers may be forced
to, if local policy allows, fall back to unencrypted DNS if this occurs.

# Privacy Considerations

Clients must be careful in determining to which DoH servers they send queries
directly. A malicious resolver that can direct queries to itself
can track or profile client activity. In order to avoid the possibility of a spoofed SVCB
record designating a malicious DoH server for a name, clients MUST ensure that
such records validate using DNSSEC ({{svcb}}), using zone apex confirmation ({{confirm-zone-apex}}),
or using domain names in TLS certificates ({{confirm-cert-name}}).

Even servers that are validly designated can risk leaking or logging information
about client lookups. Such risk can be mitigated by further restricting the list of
resolvers that are allowed for direct use based on client policy.

An adversary able to see traffic on each path segment of a DoH query (e.g., from client to
a Designated Resolver, and the Designated Resolver to an authoritative DNS server) can link queries to specific
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

## Trusted Names PvD Key

This document adds a key to the "Additional Information PvD Keys" registry {{!I-D.ietf-intarea-provisioning-domains}}.

| JSON key | Description         | Type      | Example      |
|:------------|:-----------------------|:---------------------|:------------|
| trustedNames     | Names of servers that can validate resolver designation.  | Array of Strings | [ "example.com" ] |

## DoH URI Template DNS Service Parameter

This document adds a parameter to the "Service Binding (SVCB) Parameter" registry.
The allocation request is 32768, taken from the to the First Come First Served range.

If present, this parameters indicates the URI template of a DoH server that is designated
for use with the name being resolved. This is a string encoded as UTF-8 characters.

Name:
: dohuri

SvcParamKey:
: 32768

Meaning:
: URI template for a designated DoH server

Reference:
: This document.

## Special Use Domain Name "resolver.arpa"

This document calls for the creation of the "resolver.arpa" SUDN. This will allow resolvers to respond to 
queries directed at themselves rather than a specific domain name. While this document uses "resolver.arpa"
to return SVCB records indicating DoH capability, the name is generic enough to allow future reuse for
other purposes where the resolver wishes to provide information about itself to the client. 

# Acknowledgments

Thanks to Erik Nygren, Lorenzo Colitti, Mikael Abrahamsson,
Ben Schwartz, Ask Hansen, Leif Hedstrom, Tim McCoy, Stuart Cheshire, Miguel Vega,
Joey Deng, Ted Lemon, and Elliot Briggs for their feedback and input on this document.

--- back

# Rationale for using SVCB records {#rationale}

This mechanism uses SVCB/HTTPS resource records {{!I-D.ietf-dnsop-svcb-https}} to communicate that a given
domain designates a particular DoH resolver for clients to use for subsequent queries to within the domain.

There are various other proposals for how to provide similar functionality. There are several reasons that this
mechanism has chosen SVCB records:

- Discovering encrypted resolver using DNS records keeps client logic for DNS self-contained, and allows an operator
of a DNS zone to define exactly which names should use a given DoH server.

- Using DNS records also doesn't rely on bootstrapping with higher-level application operations
(such as {{?I-D.schinazi-httpbis-doh-preference-hints}}).

- SVCB records are extensible and allow definition of parameter keys. This makes them a superior mechanism
for extensibility, as compared to approaches such as overloading TXT records. The same keys can be used both
for upgrading direct resolvers to DoH through an explicit query ({{direct}}) and for discovering designated resolvers
when issuing standard HTTPS queries ({{svcb}}).

- Clients and servers that are interested in privacy of names will already need to support SVCB records in order
to use Encrypted TLS Client Hello {{!I-D.ietf-tls-esni}}. Without encrypting names in TLS, the value of encrypting
DNS is reduced, so pairing the solutions provides the largest benefit.

- Clients that support SVCB will generally send out three queries when accessing web content on a dual-stack
network: A, AAAA, and HTTPS queries. Discovering a resolver designation for a zone as part of one of these queries,
without having to add yet another query, minimizes the total number of queries clients send. While {{?RFC5507}}
recommends adding new RRTypes for new functionality, SVCB provides an extension mechanism that simplifies
client behavior.
