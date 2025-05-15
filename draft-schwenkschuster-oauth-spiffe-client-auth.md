---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "OAuth SPIFFE Client Authentication"
category: std

docname: draft-schwenkschuster-oauth-spiffe-client-auth-latest
submissiontype: IETF
number:
date:
consensus: false
v: 3
area: AREA
workgroup: "Web Authorization Protocol"
keyword:
 - workload
 - identity
 - credential
 - exchange
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "arndt-s/oauth-spiffe-client-authentication"

author:
 -  fullname: Arndt Schwenkschuster
    organization: SPIRL
    email: arndts.ietf@gmail.com
 -  fullname: Pieter Kasselmann
    organization: SPIRL
    email: pieter@spirl.com

normative:
  RFC6749:
  RFC6755:
  RFC7517: JSON Web Keys
  RFC7521:
  RFC7523:
  RFC7591:
  RFC8705:
  SPIFFE_ID:
    title: SPIFFE-ID
    target: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
  SPIFFE_X509:
    title: X509-SVID
    target: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
  SPIFFE_JWT:
    title: JWT-SVID
    target: https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
  SPIFFE_BUNDLE:
    title: SPIFFE Bundle
    target: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
  SPIFFE_FEDERATION:
    title: SPIFFE Federation
    target: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md
  Headless_JWT:
    title: Headless-JWT
    target: foo

informative:

--- abstract

This specification profiles the Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants {{RFC7521}} and JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants {{RFC7523}} to enable the use of SPIFFE Verifiable Identity Documents (SVIDs) as client credentials in OAuth 2.0. It defines how OAuth clients with SPIFFE credentials can authenticate to OAuth authorization servers using their JWT-SVIDs or X.509-SVIDs without the need for client secrets. This approach enhances security by enabling seamless integration between SPIFFE-enabled workloads and OAuth authorization servers while eliminating the need to distribute and manage shared secrets such as static client secrets.

--- middle

# Introduction

Traditional OAuth client authentication typically relies on client secrets or private key JWT authentication, both require an out of band distribution of secret material to the OAuth client. In modern cloud-native architectures where identity is managed by SPIFFE (Secure Production Identity Framework for Everyone), there is a need to provision additional secret material for OAuth clients when verifiable credentials such as SVIDs are already available.

This specification profiles the Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants {{RFC7521}} to allow SPIFFE-enabled workloads to use their SPIFFE Verifiable Identity Documents (SVIDs) — either X.509 certificates or JWT tokens — as client credentials for OAuth 2.0 client authentication. JWT tokens make use of the profiled version of {{RFC7523}} - the JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants {{RFC7523}}.

This profile focuses specifically on client authentication rather than authorization grants. This focus is deliberate for several reasons:

1. In modern service-oriented architectures, services often need to authenticate as themselves to OAuth authorization servers.

2. Using SPIFFE as client authentication towards OAuth 2.0 authorization servers is a bridge between SPIFFE, which covers workload identity and OAuth, which covers human identity.

3. Using SPIFFE as authorization grants for authorization requests where the workload itself is the resource owner is covered by other specifications, such as {{Headless_JWT}}.

The SPIFFE profile for client authentication enables seamless integration between SPIFFE-based and OAuth-based systems, allowing applications to leverage both ecosystems without requiring additional credential management. It also enables a more secure authentication method by leveraging cryptographically verifiable identity documents rather than shared secrets.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Terminology

This specification uses the terms defined in OAuth 2.0 {{RFC6749}}, the Assertion Framework for OAuth 2.0 {{RFC7521}}, the JWT profile of it {{RFC7523}}, and the SPIFFE specifications. In particular, the following terms are particularly relevant:

**Trust Domain**: As defined in SPIFFE; A trust domain represents a single trust root. All SVIDs issued within a trust domain are verifiable via the trust domain's keys.

**SPIFFE ID**: A unified resource identifier that uniquely and specifically identifies a workload using the `spiffe` scheme. See {{SPIFFE_ID}} for details.

**SVID**: A SPIFFE Verifiable Identity Document. This document specifies the use of two types of SVIDs:

- **X.509-SVID**: An X.509 certificate that contains a SPIFFE ID in the URI SAN extension. See {{SPIFFE_X509}} for details.

- **JWT-SVID**: A JSON Web Token (JWT) that contains a SPIFFE ID in the `sub` claim. See {{SPIFFE_JWT}} for details.

**SPIFFE Bundle**: A collection of public keys and associated metadata that allow validation of SVIDs issued by a trust domain.

**SPIFFE Bundle Endpoint**: A URL that serves a SPIFFE bundle for a trust domain.

# OAuth Client Authentication Using SPIFFE

This section describes how SPIFFE identity documents can be used for OAuth 2.0 client authentication, following the patterns established in {{RFC7521}} and, in case of JWT-SVID {{RFC7523}}.

OAuth 2.0 client authentication is used to authenticate the client to the authorization server when making requests to the token endpoint. When using SPIFFE for client authentication, the client presents its SVID (either JWT-SVID or X.509-SVID) to prove its identity.

## Client Authentication with JWT-SVIDs

JWT-SVID based authentication naturally follows the JWT Profile for OAuth 2.0 Client Authentication {{RFC7523}}, with specific adaptations for SPIFFE JWT-SVIDs. {{RFC7521}} remains valid.

To identify the assertion content as a JWT-SVID this specification establishes the following client assertion type as an OAuth URI according to {{RFC6755}}:

~~~
urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
~~~

Based on {{RFC7523}} the following request parameters MUST be present to perform client authentication in the context of this specification:

* client_assertion_type: MUST be set to `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`.
* client_assertion: MUST be a single SPIFFE JWT-SVID.

To validate JWT-SVID client authentication requests the authorization server MUST:

1. Verify that the JWT is well-formed and contains all required claims (SPIFFE ID in `sub`, `aud`, and `exp`).
2. Verify that the JWT has not expired (check the `exp` claim).
3. Verify that the `aud` claim equals the endpoint of the request without fragment and query parameters.
4. Verify the JWT signature using the signing keys of the trust domains according to {{spiffe-bundle-validation}}.
5. Verify that the SPIFFE ID in the `sub` claim matches a registered client identifier or is associated with a registered client identifier.

### JWT-SVID example

The following examples illustrates an authorization_code request to the token endpoint of an OAuth 2.0 authorization server leveraging a SPIFFE JWT-SVID to authenticate the client.

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=n0esc3NRze7LTCu7iYzS6a5acc3f0ogp4&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-spiffe&
client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjR2QzhhZ3ljSHU2cm5rRUVKWUFINlZ1Q2U0Sm9Ta1BWIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbS90b2tlbiJdLCJleHAiOjE3NDcxMjQ1NDMsImlhdCI6MTc0NzEyNDI0Mywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvbXktb2F1dGgtY2xpZW50In0.Xlv5lW4cbxDsQk4l0paewG4nXOR7MxF_FMn_c27DX45Bxr2HUZf9a6Untfq5S47xpwbw495HBL6_1Lc6TMJxmw
~~~

For clarify, the SPIFFE-JWT header and body decoded:

~~~
{
  "alg": "ES256",
  "kid": "4vC8agycHu6rnkEEJYAH6VuCe4JoSkPV",
  "typ": "JWT"
}.
{
  "aud": [
    "https://as.example.com/token"
  ],
  "exp": 1747124543,
  "iat": 1747124243,
  "sub": "spiffe://example.org/my-oauth-client"
}
~~~

## Client Authentication using X509-SVID

X.509-SVID based authentication uses mutual TLS as defined in OAuth 2.0 Mutual-TLS Client Authentication {{RFC8705}}, with specific adaptations for SPIFFE X.509-SVIDs.

To authenticate using an X.509-SVID, the client establishes a mutual TLS connection with the authorization server using its X.509-SVID as the client certificate. The authorization server validates the client certificate as an X.509-SVID and extracts the SPIFFE ID from the URI SAN. The server certificate MUST be validated by the client using its system trust store, and NOT the SPIFFE trust bundle.

The request MUST include the `client_id` parameter containing the SPIFFE-ID of the client. It MUST match the URI SAN of the presented X509-SVID client credential.

The server validates the client certificates according the following rules

1. Perform standard X.509 path validation against the trust anchors according to {{spiffe-bundle-validation}}.
2. Verify that the certificate contains exactly one URI SAN with a valid SPIFFE ID.
3. Verify that the certificate is a leaf certificate (Basic Constraints extension has CA=FALSE).
4. Verify that the certificate has the `digitalSignature` key usage bit set.
5. Verify that the SPIFFE ID in the URI SAN matches a registered client identifier or is associated with a registered client identifier.

### X509-SVID Example

The following request uses a refresh token to obtain a new access token. The client is `spiffe://example.org/my-oauth-client` and is authenticted by performing this request over a mutual TLS connection.

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&
client_id=spiffe://example.org/my-oauth-client
~~~

For clarity, the presented X509-SVID client certificate to the server decoded via `openssl x509 -text` is:

~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3a:3f:ca:4a:a6:9c:58:10:d0:72:c7:39:6b:20:6f:50
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=SPIFFE, serialNumber=90586779643643322204403239935962541089
        Validity
            Not Before: May 13 08:08:11 2025 GMT
            Not After : May 13 09:08:21 2025 GMT
        Subject: C=US, O=SPIRE
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:3a:2e:ae:59:64:77:63:91:5f:90:e1:94:44:9b:
                    7d:bc:8e:10:6f:31:aa:de:9c:38:a5:ab:09:2d:45:
                    b2:92:c4:a1:75:21:84:88:61:02:5d:8c:bc:95:01:
                    33:ac:c5:44:9a:21:86:14:10:7b:2b:30:97:24:05:
                    35:41:a3:5d:8e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                ED:68:B4:9F:5C:71:FC:72:02:43:AB:2C:8C:98:7E:49:3F:66:18:C9
            X509v3 Authority Key Identifier:
                F2:67:05:2C:7E:57:2B:09:37:DE:9E:B1:71:26:0F:7D:3C:F8:A1:DC
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org/my-oauth-client
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:08:22:bf:a9:a4:25:43:76:4d:27:58:80:c3:9e:
        20:f7:0d:b9:4a:81:41:ed:a6:2d:12:f7:99:a6:e0:e9:6d:91:
        02:21:00:fb:85:e6:b9:be:de:4e:83:b0:c9:61:1e:77:b2:e4:
        4f:58:a0:fa:93:8b:b7:81:1b:53:a8:ac:d8:3b:30:7c:ce
~~~

# SPIFFE Trust Establishment and Client Registration

This specification requires previously established trust between the OAuth 2.0 Authorization Server and the SPIFFE Trust Domain. This needs to happen out of band and is not in scope of this specification. However, the mechanisms of key distribution is in scope and described in {{spiffe-bundle-validation}}.

Similar to the trust establishment, corresponding OAuth clients need to be established prior of using SPIFFE as client authentication. This is also out of scope, implementors may for example choose to levarage OAuth 2.0 dynamic client registration according to {{RFC7591}} or configure them out of band.

# SPIFFE Bundle Validation {#spiffe-bundle-validation}

This section describes how an authorization server verifies the signature of an X509 or JWT-SVID. It recommends two SPIFFE-native approaches.

Trust bundles in general MUST be keyed by the trust domain identifier to prevent mix up between trust domain and their corresponding bundles. The 2 approaches can be used in conjunction, for instance:

~~~
Trust domain "example.org": Workload API at unix:///var/secrets/spiffe/agent.sock
Trust domain "production": SPIFFE Bundle Endpoint at https://example.com/auth/spiffe/bundle.json
~~~


## SPIFFE Workload API

OAuth 2.0 Authorization Servers that have access to a SPIFFE Workload API SHOULD leverage said Workload API to retrieve the trust bundle. It is able to actively notify the authorization server of a change in the keying material in the bundle and can reduce the time to distribute updates significantly.

This requires the authorization server to be part of a SPIFFE trust domain and allows for retrieving the trust bundle of said trust domain. Additional trust domains MAY be made available via federated bundles that are part of the bundle. See {{SPIFFE_FEDERATION}} for details.

Authorization Servers MAY choose to automatically trust bundles coming from the SPIFFE Workload API. However, this is NOT RECOMMENDED and more explicit configuration which trust domains to trust SHOULD be maintained.

## SPIFFE Bundle Endpoint

Compared to the Workload API the SPIFFE Bundle Endpoint allows for key distribution over the web. The bundle endpoint exposes the signing keys for X509 and JWT-SVIDs via a JSON Web Key Set according to {{RFC7517}} over HTTPS.

Server authentication on this endpoint is available in 2 flavors, for the sake of interopability in context of this specification the WebPKI flavor MUST be used. This effectively means that the server certificate of the bundle endpoint is trusted by the authorization server accessing it. See Sec 5.2.1 of {{SPIFFE_FEDERATION}} for details.

The authorization server SHOULD periodically poll the bundle endpoint to retrieve updated trust bundles, following the refresh hint and period provided in the bundle. See {{SPIFFE_FEDERATION}} for details.

The bundle endpoint is not discoverable from the JWT-SVID and X509-SVID and MUST be configured manually out of band. Bundle endpoints MUST be keyed by the trust domain identifier.

## Alternative validation methods to avoid

## Manual configuration

In small, static environments the authorization server MAY be configured with the SPIFFE bundles manually. This approach requires human interaction to set up, rotate and manage keying material and is thus generally NOT RECOMMENDED.

## Using the JWT-SVID `iss` claim

JWT-SVIDs carrying `iss` claims could technically be validated by retrieving the signing keys via OpenID Connect Discovery or OAuth 2.0 Authorization Server Metadata. In the context of this specification these key distribution mechanisms MUST NOT be used.

> Arndt: Should we point people that want to pursue this approach to raw RFC7523?

# Security Considerations

TODO Security

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
