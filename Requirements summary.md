# Requirements summary for certificates
This document attempts to summarize the requirements for various kinds of X.509
certificates.

Please note that **the OpenSSL configuration files I provide do not encode all
requirements listed here**. In some cases, the syntax is not sufficiently
expressive: this is the case with some DN requirements for Extended Validation
certificates (where certain fields may be present only if others are). Other
requirements, such as those related to validation procedures, can not be
encoded in a configuration file at all; it is up to you to make sure they are
followed. I will also focus on fields that will need to be set manually,
especially in the case of RFC 5280-related ones (requirements which are
automatically taken care of by OpenSSL will be omitted) and will omit
less-common situations (such as LDAP CRLs for public CAs).

## Referenced documents
The following documents are referenced in this file:

* **AATL**: [*Adobe Approved Trust List Technical Requirements Version 1.4*](https://helpx.adobe.com/acrobat/kb/approved-trust-list2/_jcr_content/main-pars/download-section/download-1/file.res/aatl_technical_requirements_v14.pdf)
* **BR**: [*Baseline Requirements Certificate Policy for the Issuance and
  Management of Publicly-Trusted Certificates, version 1.4.4*](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.4.pdf) (*Note: the
  link, despite the `.pdf` extension, is a DOCX file*)
* **CS**: [*Baseline Requirements for the Issuance and Management of
  Publicly-Trusted Code Signing Certificates, version 1.1*](https://casecurity.org/wp-content/uploads/2016/09/Minimum-requirements-for-the-Issuance-and-Management-of-code-signing.pdf)
* **CTC**: [*Certificate Transparency in Chrome, May 2016*](https://docs.google.com/viewer?a=v&pid=sites&srcid=Y2hyb21pdW0ub3JnfGRldnxneDoyNjg1MWJkOWY2MmM4MzA0)
* **ETSI TS 101 862**: [*Qualified certificate profile*](http://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.03_60/ts_101862v010303p.pdf)
* **EV**: [*Guidelines For The Issuance And Management Of Extended Validation
  Certificates, version 1.6.2*](https://cabforum.org/wp-content/uploads/EV-V1_6_2.pdf)
* **EVCS**: [*Guidelines For The Issuance And Management Of Extended Validation
  Code Signing Certificates, version 1.4*](https://cabforum.org/wp-content/uploads/EV-Code-Signing-v.1.4.pdf)
* **KB281245**: [*Guidelines for enabling smart card logon with third-party certification authorities*](https://support.microsoft.com/en-us/help/281245/guidelines-for-enabling-smart-card-logon-with-third-party-certification-authorities)
* **KB291010**: [*Requirements for domain controller certificates from a third-party CA*](https://support.microsoft.com/en-us/help/291010/requirements-for-domain-controller-certificates-from-a-third-party-ca)
* **MCARP**: [*CA:Recommended Practices, Mozilla Wiki, 16 March 2017*](https://wiki.mozilla.org/index.php?title=CA:Recommended_Practices&oldid=1165923)
* **MCARR**: [*CA:Recommendations for Roots, Mozilla Wiki, 6 April 2011*](https://wiki.mozilla.org/index.php?title=CA:Recommendations_for_Roots&oldid=296551)
* **MRSP**: [*Mozilla Root Store Policy, version 2.4.1*](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
* **MTRPR**: [*Microsoft Trusted Root Program Requirements, version 2.0*](http://aka.ms/RootCert)
* **RFC 3161**: [*Internet X.509 Public Key Infrastructure Time-Stamp Protocol
  \(TSP\)*](https://datatracker.ietf.org/doc/rfc3161/)
* **RFC 4055**: [*Additional Algorithms and Identifiers for RSA Cryptography
  for use in the Internet X.509 Public Key Infrastructure Certificate and
  Certificate Revocation List \(CRL\) Profile*](https://datatracker.ietf.org/doc/rfc4055/)
* **RFC 4491**: [*Using the GOST R 34.10-94, GOST R 34.10-2001, and GOST R
  34.11-94 Algorithms with the Internet X.509 Public Key Infrastructure
  Certificate and CRL Profile*](https://datatracker.ietf.org/doc/rfc4491/)
* **RFC 5246**: [*The Transport Layer Security (TLS) Protocol Version
  1.2*](https://datatracker.ietf.org/doc/rfc5246/)
* **RFC 5280**: [*Internet X.509 Public Key Infrastructure Certificate and
  Certificate Revocation List \(CRL\) Profile*](https://datatracker.ietf.org/doc/rfc5280/).
  This is *the* main source for certificate profile details; I recommend to
  read this document in its entirety.
* **RFC 5480**: [*Elliptic Curve Cryptography Subject Public Key
  Information*](https://datatracker.ietf.org/doc/rfc5480/)
* **RFC 5750**: [*Secure/Multipurpose Internet Mail Extensions \(S/MIME\) Version
  3.2 Certificate Handling*](https://datatracker.ietf.org/doc/rfc5750/)
* **RFC 5756**: [*Updates for RSAES-OAEP and RSASSA-PSS Algorithm
  Parameters*](https://datatracker.ietf.org/doc/rfc5756/)
* **RFC 5758**: [*Internet X.509 Public Key Infrastructure: Additional
  Algorithms and Identifiers for DSA and ECDSA*](https://datatracker.ietf.org/doc/rfc5758/)
* **RFC 6818**: [*Updates to the Internet X.509 Public Key Infrastructure
  Certificate and Certificate Revocation List (CRL)
  Profile*](https://datatracker.ietf.org/doc/rfc5246/)
* **RFC 6960**: [*X.509 Internet Public Key Infrastructure Online Certificate
  Status Protocol - OCSP*](https://datatracker.ietf.org/doc/rfc6960/)
* **RFC 6962**: [*Certificate Transparency*](https://datatracker.ietf.org/doc/rfc6962/)

## Common requirements
These requirements apply to all profiles listed in the rest of this document.

* Certificates MUST be X.509v3 ones (BR, section 7.1.1; RFC5246, section
  7.4.2, for Web servers; AATL, requirement 2, for PDF signing certificates;
  MTRPR, section 4.A.1, for root certificates)
* The certificate serial number MUST be a unique, positive, non-sequential
  integer, at most 20 octets long, containing at least 64 bits of output from a
  CSPRNG (RFC 5280, section 4.1.2.2; BR, section 7.1; CS, section 9.6; MSRP,
  section 5.2)
* The certificate signing algorithm should be one of those listed in RFC 3279
  or its updates (RFC 4055, RFC 4491, RFC 5480, RFC 5756, RFC 5758) for maximum
  compatibility (each software implementation that conforms to RFC5280 MUST
  support them); other algorithms can be used (RFC 5280, section 4.1.2.3)
* The Issuer field MUST contain a non-empty Distinguished Name and it MUST be
  encoded as an `UTF8String` or as a `printableString` (RFC 5280, section
  4.1.2.4)
* The Subject Distinguished Name MUST be unique for each physical subject (note
  that this still allows issuing multiple certificates with the same DN to the
  same subject; RFC 5280, section 4.1.2.6)
* E-mail addresses MUST be encoded as `rfc822Name`s in the Subject Alternative
  Name extension. Putting them in the `E` component of the Subject Distinguished
  Name is deprecated; if that component is present, the e-mail address MUST be
  encoded as an `IA5String` and be at most 255 characters long (RFC 5280,
  section 4.1.2.6, and RFC 5750, sections 3 and 4.4.3)
* The algorithm and method used to encode the public key and to identify the
  algorithm with which the key is used MUST be chosen among the ones listed in
  RFC 3279 or its updates (RFC 4055, RFC 4491, RFC 5480, RFC 5756, RFC 5758)
  (RFC 5280, section 4.1.2.7)
* The Authority Key Identifier extension MUST be present (it MAY be omitted in
  root CAs) and MUST be non-critical; it is recommended to derive it from the
  authority public key instead of the issuer name and serial number (RFC 5280,
  section 4.2.1.1)
* The Subject Key Identifier extension MUST be present in CA certificates and
  SHOULD be present in end entity certificates. It MUST be non-critical
  (RFC 5280, section 4.2.1.2)
* The Key Usage extension MUST be present if the certificate is used to
  validate signatures; it SHOULD be critical. The usage bits MUST be consistent
  with the key usage purposes:

    Key usage bit      | Usage
    -------------------|------
    `digitalSignature` | The public key is used to verify signatures other than those on certificates and CRLs
    `nonRepudiation`   | The digital signatures made using the key (not on certificates/CRLs) can not be denied
    `keyEncipherment`  | The public key is used to encipher private or secret keys (e.g. symmetric session keys in TLS)
    `dataEncipherment` | The public key is used to encipher data directly
    `keyAgreement`     | The public key is used for key agreement
    `keyCertSign`      | The public key is used to verify signatures on public key certificates (this requires `CA:TRUE` in the Basic Constraints extension, see below)
    `cRLSign`          | The public key is used to verify signatures on CRLs
    `encipherOnly`     | If `keyAgreement` is set, the public key may be used only for enciphering data while performing key agreement
    `decipherOnly`     | If `keyAgreement` is set, the public key may be used only for deciphering data while performing key agreement

    as well as with the certificate and key type:

    Key type    | Certificate type | Permissible key usage bits
    ------------|------------------|---------------------------
    RSA         | CA/CRL issuer    | `digitalSignature`, `nonRepudiation`, `keyEncipherment` (SHOULD NOT be present), `dataEncipherment` (SHOULD NOT be present), `keyCertSign`, `cRLSign`
    RSA         | End entity       | `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`
    DSA         | CA/CRL issuer    | `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign`
    DSA         | End entity       | `digitalSignature`, `nonRepudiation`
    DH-KEK      | All              | `keyAgreement`, `encipherOnly`, `decipherOnly`
    KEA         | All              | `keyAgreement`, `encipherOnly`, `decipherOnly`
    ECDSA/ECDH  | CA/CRL issuer    | `digitalSignature`, `nonRepudiation`, `keyAgreement`, `encipherOnly`, `decipherOnly`, `keyCertSign`, `cRLSign`
    ECDSA/ECDH  | End entity       | `digitalSignature`, `nonRepudiation`, `keyAgreement`, `encipherOnly`, `decipherOnly`
    ECPublicKey | CA/CRL issuer    | `digitalSignature`, `nonRepudiation`, `keyAgreement`, `encipherOnly`, `decipherOnly`, `keyCertSign`, `cRLSign`
    ECPublicKey | End entity       | `digitalSignature`, `nonRepudiation`, `keyAgreement`, `encipherOnly`, `decipherOnly`
    ecDH/ecMQV  | End entity       | `keyAgreement`, `encipherOnly`, `decipherOnly`

    (`encipherOnly`/`decipherOnly` can be present only if `keyAgreement` is set
    and MUST NOT be present at the same time) (RFC 5280, section 4.2.1.3; RFC
    3279, sections 2.3.1-2.3.5)

* Certificate policies MUST consist of one or more OIDs, each of which MUST
  appear only once, and of some optional qualifiers. The `userNotice` field
  SHOULD appear only in CA certificates issued to third parties and in end
  entity certificates; the `noticeRef` field SHOULD NOT be present; the
  `explicitText` MUST be at most 200 characters long, SHOULD be encoded as an
  `UTF8String` and it SHOULD NOT include control characters (RFC 5280, section
  4.2.1.4)
* Policy mappings MUST be used only in CA certificates; if the extension is
  present, it SHOULD be critical. Each `issuerDomainPolicy` should also be
  asserted in a certificate policy in the same certificate. No mappings to/from
  `anyPolicy` are allowed (RFC 5280, section 4.2.1.5)
* The Subject Alternative Name extension MUST be used to bind DNS/e-mail
  resources. If the only subject identity is an alternative name, the extension
  MUST be critical; it SHOULD be non-critical otherwise (RFC 5280, section
  4.2.1.6)
* The Issuer Alternative Name extension SHOULD be non-critical (RFC 5280,
  section 4.2.1.7)
* The Subject Directory Attributes extension MUST be non-critical (RFC 5280,
  section 4.2.1.8)
* The Basic Constraints extension MUST be present and MUST be critical in CA
  certificates (with the exception of CA certificates used exclusively for
  purposes other than validating digital signatures on certificates); it MAY
  be present in end entity certificates. If `CA` is `FALSE`, the `keyCertSign`
  bit in the Key Usage extension MUST NOT be asserted (RFC 5280, section
  4.2.1.9; RFC 5750, section 4.4.1)
* The Name Constraints extension MUST be present only in CA certificates and
  MUST be critical; constraints MUST NOT be imposed on `x400Addresses`,
  `ediPartyNames` or `registeredIDs`; the list of constraints MUST NOT be empty
  (RFC 5280, section 4.2.1.10)
* The Policy Constraints extension can be used only in sub-CA certificates;
  it MUST be critical (RFC 5280, section 4.2.1.11)
* The Extended Key Usage values MUST be consistent with the bits enabled in the
  Key Usage extension. If the `anyExtendedKeyUsage` value is present, the
  extension SHOULD NOT be marked as critical, otherwise, it MAY be critical or
  non-critical (RFC 5280, section 4.2.1.12)
* No Extended Key Usage values that do not apply in the context of the public
  Internet (with limited exceptions) or that will mislead the public about the
  information verified by the CA (BR, section 7.1.2.4)
* In the CRL Distribution Point extension, the URIs using the HTTP scheme
  MUST point to a DER-encoded CRL served with the MIME type
  `application/pkix-crl` (RFC 5280, section 4.2.1.13).
* If the Inhibit anyPolicy extension is present, it MUST be critical (RFC 5280,
  section 4.2.1.14)
* If the Freshest CRL extension is present, it MUST be non-critical (RFC 5280,
  section 4.2.1.15)
* If the Authority Information Access extension is present, it MUST be
  non-critical; if the `id-ad-caIssuers` access method is present and the CA
  certificate is provided as a single DER certificate over HTTP, the MIME type
  with which the certificate is served should be `application/pkix-cert`; if
  the `id-ad-ocsp method` is present, the URI should point to an OCSP responder
  conformant to RFC 2560 (now obsoleted by RFC 6960) (RFC 5280, section 4.2.21,
  and RFC 6960, section 3.1)
* If the Subject Information Access extension is present, it MUST be
  non-critical. The `id-ad-timeStamping` OID can be used to specify the
  location of a time stamping server provided by the CA: in that case, the
  location MUST be an HTTP/FTP URI or an e-mail address (RFC 5280, section
  4.2.2.2)
* If Certificate Transparency precertificates are to be included in the final
  certificate, the CA must first create a certificate that is identical to the
  one to be signed, except for the addition of an extension having
  `1.3.6.1.4.1.11129.2.4.3` as its OID and ASN.1 `NULL` data as its value; it
  must be signed either with the CA key or with an auxiliary certificate
  (*Precertificate Signing Certificate*) having the following profile:

    * Basic Constraints: `CA:TRUE`;
    * Extended Key Usage: Certificate Transparency (OID
      `1.3.6.1.4.1.11129.2.4.4`)

    The timestamp list returned by the Certificate Transparency server should
    be then encoded as an ASN.1 octet string and inserted as a certificate
    extension with OID `1.3.6.1.4.1.11129.2.4.2` (RFC 6962, sections 3.1 and
    3.3)

* CAs MUST reject certificate requests having a known weak private key or not
  meeting the digest algorithm/key size requirements for each profile (BR,
  section 6.1.1.3; CS, section 9.5)
* The digest algorithm used MUST be SHA-256, SHA-384 or SHA-512 (BR, sections
  6.1.5 and 7.1.3; AATL, requirement 9; CS, appendix A; MSRP, section 5.1;
  MTRPR, section 4.B)
* For RSA certificates, the minimum modulus size MUST be 2048 bits and MUST be
  divisible by 8; in the case of code signing/time stamping certificates and CA
  chains, the minimum modulus size MUST be 4096 bits (BR, section 6.1.5; AATL,
  requirement 9; CS, appendix A; MSRP, section 5.1; MTRPR, section 4.B)
* For ECC certificates, the certificate MUST use one of the following NIST
  curves: P-256 with SHA-256 or P-384 with SHA-384. (BR, section 6.1.5; AATL,
  requirement 9, mandates "at least P-256"; CS, appendix A; MSRP, section 5.1;
  MTRPR, section 4.B)
* For DSA certificates, the minimum modulus size MUST be 2048 bits and the
  minimum divisor size MUST be 224 or 256 bits (BR, section 6.1.5; CS, appendix
  A)
* CAs MUST NOT issue certificates having ASN.1 decoding errors, invalid public
  keys, duplicate issuer names and serial numbers (with the exception of
  Certificate Transparency precertificates), incorrect extensions, CRL
  Distribution Points or OCSP responder URLs for which no operational service
  exists (MSRP, section 5.2)

## Root CA
* Root CA keys MUST be used to sign only:

    * the root CA certificate;
    * certificates for subordinate CAs;
    * cross certificates;
    * certificate for infrastructure purposes (e.g. OCSP responder certificates);
    * certificate issued solely for the purpose of testing products with
      certificates issued by a root CA

    (BR, section 6.1.7; CS, section 12)

* The certificate subject MUST contain the `countryName` and the
  `organizationName` fields; the `commonName` SHOULD be present (BR, section
  7.1.2.1; MCARR, section "Contents of the Root")
* The CA name MUST be meaningful, MUST identify the publisher, MUST be unique
  and MUST be in a language appropriate for the CA market and readable by a
  typical customer in that market (AATL, requirement 3; MTRPR, section 4.A.1)
* The key pair MUST be generated and stored on a FIPS 140-2 Level 3 or
  equivalent HSM (AATL, requirement 6)
* The root CA validity should range from 8 to 25 years (MTRPR, section 4.A.2-3)
* Private keys and subject names MUST be unique per root certificate (MTRPR,
  section 4.A.6)
* The Basic Constraints extension MUST be present, critical and set to
  `CA:TRUE`; `pathLenConstraint` SHOULD NOT be present (BR, section 7.1.2.1;
  MTRPR, section 4.A.1)
* The Key Usage extension MUST be present and critical. `keyCertSign` and
  `cRLSign` MUST be set, other bits MUST NOT be set (BR, section 7.1.2.1; MTRPR,
  section 4.A.1)
* The Certificate Policies extension SHOULD NOT be present (BR, sections
  7.1.2.1 and 7.1.6.2; CS, section 9.3.2)
* The Extended Key Usage extension MUST NOT be present (BR, section 7.1.2.1)
* The Subject Alternative Name MAY contain a support contact e-mail address
  (MCARR, section "Contents of the Root")

## Common requirements for intermediate CA certificates
* Separate intermediate CAs MUST be used for Web server, S/MIME, code signing
  and time stamping certificates (MTRPR, section 4.A.11)
* The CA name MUST be meaningful (AATL, requirement 3)
* The certificate subject MUST contain the `countryName` and the
  `organizationName` fields (BR, section 7.1.2.2)
* The key pair MUST be generated and stored on a FIPS 140-2 Level 3 or
  equivalent HSM (AATL, requirement 6)
* The Certificate Policies extension MUST be present and SHOULD NOT be marked
  critical. The policy identifier is required. If the subordinate CA is not
  affiliated with the entity that controls the root CA, the policy qualifier ID
  MUST contain an explicit policy identifier indicating the subordinate CA
  adherence to and compliance with the Baseline Requirements (either a
  CA/Browser Forum reserved identifier or a CA-specific OID), MUST NOT contain
  `anyPolicy` and the policy qualifier ID MAY be set to `id-qt 1`; otherwise, it
  MAY contain an explicit policy identifier and/or `anyPolicy` (in the case of
  code signing certificates, it MUST contain the CA/Browser Forum reserved
  identifier for code signing and MAY include the `anyPolicy` identifier). The
  CPS URI MAY (MUST in the case of CAs issuing code signing/time stamping
  certificates where the subordinate CA is not affiliated with the root CA) be
  set to the HTTP URL for the CPS (BR, sections 7.1.2.2 and 7.1.6.3; CS,
  section 9.3.3 and appendix B)
* The CRL Distribution Points extension MUST be present, MUST be non-critical
  and it MUST point to the HTTP URL for the CRL service (BR, section 7.1.2.2;
  AATL, requirement 17; CS, appendix B; MTRPR, section 4.C.4)
* The Authority Information Access extension MUST be present, MUST be
  non-critical and MUST contain the HTTP URL for the OCSP responder (unless the
  certificate subject staples the OCSP response in its TLS handshakes); it
  SHOULD also contain the HTTP URL at which the issuing CA certificate can be
  retrieved (BR, section 7.1.2.2; AATL, requirement 17; CS, appendix B;
  MTRPR, section 4.C.4)
* The Basic Constraints extension MUST be present, critical and set to
  `CA:TRUE`; `pathLenConstraint` MAY be present (BR, section 7.1.2.2; CS,
  appendix B)
* The Key Usage extension MUST be present and critical. `keyCertSign` and
  `cRLSign` MUST be set; if the certificate is used to sign OCSP responses,
  `digitalSignature` MUST be set (BR, section 7.1.2.2; CS, appendix B)
* The Name Constraints extension, if present, SHOULD be critical (BR, section
  7.1.2.2)
* If the subordinate CA certificate should be technically constrained, the
  Name Constraints extension MUST be present; `permittedSubtrees` MUST contain
  the DNS names/IP addresses over which the subordinate CA applicants have
  control and the directory name (if any). If the subordinate CA is not allowed
  to issue certificates to IP addresses, the entire IPv4 and IPv6 ranges MUST
  be listed in `excludedSubtrees` (respectively, as `0.0.0.0/0` and as `::0/0`);
  otherwise, at least one IP address MUST be present; similarly, if the CA is
  not allowed to issue certificates to DNS names, a zero length DNS name MUST
  be listed in `excludedSubtrees`, otherwise, at least one name MUST be listed
  in `permittedSubtrees` (BR, section 7.1.5)
* Government Web server CAs MUST be name constrained to `.gov` domains and may
  issue certificates only to the country codes the country has sovereign
  control over (MTRPR, section 4.A.8)
* The Extended Key Usage SHOULD be non-critical; if the subordinate CA
  certificate should be technically constrained, `id-kp-serverAuth`,
  `id-kp-clientAuth` or both MUST be present, and the `anyExtendedKeyUsage` ID
  MUST NOT appear. In case `id-kp-serverAuth` is present, the certificate must
  be name constrained; in case `id-kp-emailProtection` is present, all end
  entity certificates MUST only include e-mail addresses that the issuing CA has
  confirmed that the subordinate CA is authorized to use (BR, sections 7.1.2.2
  and 7.1.5; CS, appendix B; MSRP, section 5.3.1)

## Common requirements for end entity certificates
* End entity certificates MUST have a maximum validity period of 39 months
  (825 days if they are issued after March 1st, 2018 or if they are EV
  certificates); EV certificates SHOULD have a maximum validity period of 12
  months, and MUST have a maximum validity of 15 months if an `.onion` domain is
  included (BR, section 6.3.2; EV, section 9.4 and appendix F; CS, section 9.4)
* The Certificate Policies extension MUST be present and SHOULD NOT be critical;
  the policy identifier is required and MUST include one of the reserved
  CA/Browser Forum OIDs depending on the validation type; the policy identifier
  ID, if present, SHOULD be `id-qt 1` and the `cPSuri` SHOULD be the HTTP URI
  pointing to the subordinate CA CPS (BR, section 7.1.2.3; CS, section 9.3.4
  and appendix B; MTRPR, section 4.A.15)
* If the CRL Distribution Points extension is present, it MUST NOT be critical
  and it MUST contain the HTTP URL to the CA CRL (BR, section 7.1.2.3; CS,
  appendix B)
* The Authority Information Access extension MUST be present and MUST NOT be
  critical; it MUST contain the HTTP URL of the OCSP responder for the CA
  (except when the CA mandates subscribers to perform OCSP stapling) and
  SHOULD contain the HTTP URL to the issuing CA certificate (mandatory for code
  signing/time stamping certificates) (BR, section 7.1.2.3; AATL, requirement
  17; CS, appendix B; MTRPR, section 4.A.5, mandates OCSP for Web server
  certificates and OCSP or a CRL for other certificates)
* In the Basic Constraints extension, the CA field MUST be `FALSE` and the
  `pathLenConstraint` field MUST be absent (BR, section 7.1.2.3; CS, appendix B;
  MTRPR, section 4.A.16)
* If the Key Usage extension is present, the bits `keyCertSign` and `cRLSign`
  MUST NOT be set (BR, section 7.1.2.3)
* The Extended Key Usage field MUST be include at least one of
  `id-kp-serverAuth` or `id-kp-clientAuth`; `id-kp-emailProtection` MAY be
  present; `anyExtendedKeyUsage` MUST NOT be present; other values SHOULD NOT
  be present (BR, section 7.1.2.3, overridden by some more specific certificate
  profiles; MTRPR, section 4.A.18)
* The Subject Alternative Name MUST be present, MUST contain at least one domain
  entry, each of which MUST be either a `dNSName` containing an FQDN or an
  `iPAddress` containing the IP address of a server; wildcard FQDNs are
  permitted, reserved IP addresses and internal names are prohibited (BR,
  section 7.1.4.2.1)
* The Subject Distinguished Name `commonName` field is optional (it is
  deprecated); if it is present, it MUST contain a single IP address or FQDN
  among those listed in the Subject Alternative Name extension (BR, section
  7.1.4.2.2)
* The Subject Distinguished Name `organizationName` field is prohibited if the
  "domain validated" policy OID is present or if the "individual validated"
  policy OID is present and the `givenName` and `surname` fields are present,
  mandatory if the "organization validated" policy OID is present, or if the
  "individual validated" policy OID is present and the `givenName` and `surname`
  fields are absent, optional otherwise; if it is present, it MUST contain the
  certificate subject name/DBA. It MAY also be used to convey a natural
  person's subject name or DBA (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `givenName` field is prohibited if the "domain
  validated" policy OID is present or if the "individual validated" policy OID
  is present and the `organizationName` field is present, mandatory if the
  "individual validated" policy OID is present and the `organizationName` field
  is absent; if it is present, it MUST contain the given name of the natural
  person corresponding to the subject, and the certificate MUST carry the
  "individual validated" policy OID (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name surname field is prohibited if the "domain
  validated" policy OID is present, or if the "individual validated" policy OID
  is present and the `organizationName` field is present, mandatory if the
  "individual validated" policy OID is present and the `organizationName` field
  is absent; if it is present, it MUST contain the surname of the natural
  person corresponding to the subject, and the certificate MUST carry the
  "individual validated" policy OID (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `streetAddress` field is optional if the
  `organizationName`, `givenName` or `surname` fields are present and the
  "domain validated" policy OID is not present and is prohibited otherwise; if
  it is present, it MUST contain the street address information of the subject
  (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `localityName` field is required if the
  `organizationName`, `givenName` or `surname` fields are present and the
  `stateOrProvinceName` field is absent; it is optional if the
  `stateOrProvinceName` and the `organizationName`, `givenName` or `surname`
  fields are present; it is prohibited if the `organizationName`, `givenName`
  or `surname` fields are absent, or if the "domain validated" policy OID is
  present. If it is present, it MUST contain the locality information of the
  subject; if the `countryCode` field is `XX`, this field MAY contain the
  subject's locality and/or state or province (BR, sections 7.1.4.2.2 and
  7.1.6.1)
* The Subject Distinguished Name `stateOrProvinceName` field is required if the
  `organizationName`, `givenName` or `surname` fields are present and the
  `localityName` field is absent; it is optional if the `localityName` and the
  `organizationName`, `givenName` or `surname` fields are present; it is
  prohibited if the `organizationName`, `givenName` or `surname` fields are
  absent, or if the "domain validated" policy OID is present. If it is present,
  it MUST contain the state or province information of the subject; if the
  `countryCode` field is `XX`, this field MAY contain the full name of the
  subject's country information (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `postalCode` field is optional if the
  `organizationName`, `givenName` or `surname` fields are present; it is
  prohibited if the `organizationName`, `givenName` or `surname` fields are
  absent. If it is present, it MUST contain the zip or postal information of the
  subject. It is prohibited if the "domain validated" policy OID is present (BR,
  sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `countryName` field is required if the
  `organizationName`, `givenName` or `surname` fields are present, or if the
  "organization validated" or "individual validated" policy OID is present; it
  is optional otherwise. If the `organizationName` field is present, the
  `countryName` field MUST contain the two-letter ISO 3166-1 country code
  associated with the location of the subject, otherwise, it MAY contain such
  code. If a country is not represented by an ISO 3166-1 country code, `XX` MAY
  be used (BR, sections 7.1.4.2.2 and 7.1.6.1)
* The Subject Distinguished Name `organizationalName` field is optional and MUST
  NOT include any information referring to a specific natural person or entity,
  unless such information was verified by the CA and the certificate also
  contains the `organizationName`, `givenName`, `surname`, `localityName` and
  `countryName` fields (BR, section 7.1.4.2.2)
* Other Subject Distinguished Name fields MUST contain information verified by
  the CA and MUST NOT contain metadata/indications that the value is absent,
  incomplete or not applicable (BR, section 7.1.4.2.2)

## CA for personal certificates
* Certificates to be used for S/MIME should use an RSA keypair (with a public
  key size of at most 4096 bits) and use SHA-256 hashes. This is the
  configuration that MUST be supported by RFC 5750-compliant software. The
  following configuration SHOULD also be supported (and will probably be
  required in future RFCs): certificates using DSA keypairs (with a public key
  size of at most 3072 bits), using SHA-256 hashes; certificates using RSA
  keypairs with a public key size greater than 4096 bits, using SHA-256 hashes;
  RSA-PSS certificates using SHA-256 hashes (RFC 5750, section 4.3)
* Certificates to be used for S/MIME MUST include the `emailProtection` or the
  `anyExtendedKeyUsage` values in the Extended Key Usage extension (RFC 5750,
  section 4.4.4)

## EV Web server CA
* Subordinate CA certificates issued to entities other than the issuing CA MUST
  contain policy identifiers that explicitly identify the EV policies
  implemented by the subordinate CA, the `policyQualifierId` `id-qt 1` and an
  HTTP `cPSuri` that points to the root CA CPS; subordinate CA certificates
  issued to the issuing CA MAY contain the `anyPolicy` identifier (EV, sections
  9.3.4 and 9.7)

## Code signing CA
* The Extended Key Usage MUST include `id-kp-codeSigning`; `documentSigning` and
  `emailProtection` MAY be present; `anyExtendedKeyUsage` and `serverAuth` MUST
  NOT be present; other values SHOULD NOT be present (if they are present, the
  CA MUST have an agreement in place with a software vendor requiring that value
  in order to issue a platform-specific code signing certificate) (CS,
  appendix B)

## Time stamping CA
* The Extended Key Usage MUST include `id-kp-timeStamping`;
  `anyExtendedKeyUsage` MUST NOT be present; other values SHOULD NOT be present
  (if they are present, the CA MUST have an agreement in place with a software
  vendor requiring that value in order to issue a platform-specific code signing
  certificate) (CS, appendix B)

## Qualified certificate CA
**Note: this profile is based only on the ETSI TS 101 862 standard. Each EU
member state might impose additional requirements.**

* The name appearing in the subject field SHOULD be an officially registered
  name of the issuing organization (RFC 3739, section 3.1.1)
* The DN SHALL be specified using the `domainComponent`, `countryName`,
  `stateOrProvinceName`, `organizationName`, `localityName` and `serialNumber`
  components; other attributes MAY be present. The `countryName` attribute
  MUST be present and MUST be the country in which the certificate issuer is
  established (RFC 3739, section 3.1.1)

## Smart card logon: domain controller certificate
* A CRL distribution point MUST be populated (KB291010)
* The certificate subject name MAY contain the distinguished name of the server
  object (KB291010)
* The Key Usage field MUST have the `digitalSignature` and `keyEncipherment`
  bits set (KB291010)
* The Basic Constraints field MAY be set to `CA:FALSE` with `pathLenConstraint`
  absent (KB291010)
* The Extended Key Usage field MUST include `clientAuth` and `serverAuth`
  (KB291010)
* The Subject Alternative Name MUST include the DNS name and, if SMTP
  replication is used, the domain controller object GUID encoded with the OID
  `1.3.6.1.4.1.311.25.1` (KB291010)
* The certificate template MUST have an extension including the BMP data
  `DomainController` (KB291010)

## Smart card logon: smart card certificate
* A CRL distribution point MUST be populated (KB281245)
* The Key Usage field MUST have only the `digitalSignature` bit set (KB281245)
* The Extended Key Usage field MUST include Smart Card Logon and (if SSL
  authentication is used) Client Authentication (KB281245)
* The Subject Alternative Name MUST include an `otherName` in UPN form,
  encoded as a `UTF8String` (KB281245)

## PDF signing
* The key pair MUST be generated and stored on a FIPS 140-2 Level 2, Common
  Criteria, ISO 15408, Protection Profile: CWA 14169 or a European Secure
  Signature Creation Device (AATL, requirement 11)
* The CRL Distribution Points extension MUST be present (AATL, requirement 17)
* Adobe-specific OIDs SHOULD be present (AATL, requirement 19)
* The signer MUST have exclusive, physical control over their private key
  (AATL, requirement 10)

## Web server
* The following key usage bits MUST be enabled, depending on the key exchange
  algorithm used:

    Algorithm          | Bits to enable
    -------------------|-------------------
    RSA, RSA/PSK       | `keyEncipherment`
    DHE_RSA, ECDHE_RSA | `digitalSignature`
    DH_DSS, DH_RSA     | `keyAgreement`

    (RFC 5246, section 7.4.2)

* Validated FQDNs MAY be listed as `dNSNames` in the Subject Alternative Name
  extension or in subordinate CA certificates as `dNSNames` in
  `permittedSubtrees` within the Name Constraints extension (BR, section
  3.2.2.4)
* Validated IP addresses MAY be listed as `IPAddress` in the Subject Alternative
  Name extension or in subordinate CA certificates as `IPAddress` in
  `permittedSubtrees` within the Name Constraints extension (BR, section
  3.2.2.5)
* Certificate requests MUST include at least one FQDN or IP address to be
  included into the Subject Alternative Name extension (BR, section 4.2.1)
* CAs SHOULD NOT issue certificates containing a new gTLD under consideration
  by ICANN (BR, section 4.2.2)

## Extended Validation Web server
* The following key usage bits MUST be enabled, depending on the key exchange
  algorithm used:

    Algorithm          | Bits to enable
    -------------------|-------------------
    RSA, RSA/PSK       | `keyEncipherment`
    DHE_RSA, ECDHE_RSA | `digitalSignature`
    DH_DSS, DH_RSA     | `keyAgreement`

    (RFC 5246, section 7.4.2)

* Validated FQDNs MAY be listed as `dNSNames` in the Subject Alternative Name
  extension or in subordinate CA certificates as `dNSNames` in
  `permittedSubtrees` within the Name Constraints extension (BR, section
  3.2.2.4)
* Validated IP addresses MAY be listed as `IPAddress` in the Subject Alternative
  Name extension or in subordinate CA certificates as `IPAddress` in
  `permittedSubtrees` within the Name Constraints extension (BR, section
  3.2.2.5)
* Certificate requests MUST include at least one FQDN or IP address to be
  included into the Subject Alternative Name extension (BR, section 4.2.1)
* CAs SHOULD NOT issue certificates containing a new gTLD under consideration
  by ICANN (BR, section 4.2.2)
* In the Subject Distinguished Name, the `commonName`, if present, MUST contain
  a single domain name; wildcards are not allowed, except in the case where the
  domain is an `.onion` one and the wildcard character is in the leftmost
  position (EV, section 9.2.3 and appendix F)
* In the Subject Distinguished Name, the `organizationName` field is required
  and can be at most 64 characters long; an assumed name/DBA MAY be used, as
  long as it is followed by the full organization name in parenthesis. If the
  field contents would exceed 64 characters, the CA MAY abbreviate parts of the
  organization name and/or omit non-material words; if it is not possible to do
  so, the CA MUST NOT issue the certificate (EV, section 9.2.1)
* In the Subject Distinguished Name, the `businessCategory` field is required
  and MUST contain `Private Organization`, `Government Entity`,
  `Business Entity` or `Non-Commercial Entity` depending on the entity type
  (EV, section 9.2.4)
* In the Subject Distinguished Name, the `jurisdictionLocalityName`,
  `jurisdictionStateOrProvinceName` and `jurisdictionCountryName` are required
  (if the incorporating/registration agency is at the country level, only
  `jurisdictionCountryName` is required; if the agency is at the state/province
  level, both `jurisdictionCountryName` and `jurisdictionStateOrProvinceName`
  are required; if the agency is at the locality level, all mentioned fields are
  required). The country information MUST be specified using the applicable
  ISO country code; the locality and state/province information MUST be
  specified using the full name (EV, section 9.2.5)
* In the Subject Distinguished Name, the `serialNumber` field is required; it
  MUST contain the registration number or, in case no such number is issued,
  the registration date in a commonly-recognized format (for private
  organizations or business entities) or appropriate language to indicate that
  the subject is a government entity (for government entities (EV, section
  9.2.6)
* In the Subject Distinguished Name, the `localityName`, `stateOrProvinceName`
  and `countryName` are required; the `streetAddress` and `postalCode` fields
  are optional (EV, section 9.2.7)
* In the Subject Distinguished Name, attributes SHALL NOT include fully
  qualified domain names/organization information (except as expressly
  specified) (EV, section 9.2.8)
* In the Subject Alternative Name, the `dNSName` field is required; wildcards
  are not allowed (EV, section 9.2.2)
* Each certificate MUST contain a policy identifier OID that is either the
  CA/Browser Forum EV identifier or an OID that marks the certificate as being
  an EV certificate; the policy qualifier ID MUST be `id-qt 1` and the `cPSuri`
  MUST be an HTTP URL pointing to the subordinate CA CPS (EV, sections 9.3.2
  and 9.7)
* If no OCSP responder location is stored in the certificate, the
  `cRLDistributionPoint` extension MUST be present (EV, section 9.7)
* EV certificates MUST be submitted to at least two CT logs (three for
  certificates valid for at least 15 and at most 27 months), at least one of
  which MUST be Google-operated and at least another MUST not; the SCTs must
  either be embedded in the certificate or presented via a TLS extension /
  embedded in a stapled OCSP response (CTC)

## Code signing
* The subject Common Name MUST be present and MUST contain the subject's legal
  name (CS, section 9.2.2)
* The subject Domain Component field MUST NOT be present (CS, section 9.2.3)
* In the Subject Distinguished Name, the Organization field is required; it
  MUST contain the subject's name/DBA; the CA MAY include information that
  differs slightly from the verified name (e.g. common, locally accepted
  abbreviations), as long as it documents the difference, MAY use the field to
  convey a natural person subject's name/DBA, and MUST have a process to check
  that the information included in this field is not misleading (CS, section
  9.2.4)
* In the Subject Distinguished Name, the `streetAddress` field is optional; if
  present, it MUST contain the subject's street address information (CS,
  section 9.2.4)
* In the Subject Distinguished Name, the `localityName` field is required if the
  `stateOrProvinceName` field is absent, optional otherwise; if present, it MUST
  contain the subject's locality name information (or, if the `countryName`
  field is `XX`, it MAY contain the subject's locality and/or state/province
  information) (CS, section 9.2.4)
* In the Subject Distinguished Name, the `stateOrProvinceName` field is required
  if the `localityName` field is absent, optional otherwise; if present, it MUST
  contain the subject's state/province information (or, if the `countryName`
  field is `XX`, it MAY contain the full name of the subject's country
  information) (CS, section 9.2.4)
* In the Subject Distinguished Name, the `postalCode` field is optional; if
  present, it MUST contain the subject's zip information (CS, section 9.2.4)
* In the Subject Distinguished Name, the `countryName` field is required and MUST
  contain the two-letter ISO 3166-1 code of the country associated with the
  subject location; if the country was not allocated such a code, the CA MAY
  use `XX` (CS, section 9.2.4)
* In the Subject Distinguished Name, the `organizationalUnitName` field is
  optional; if present, it MUST NOT include text referring to a specific person
  or entity unless that information was verified by the CA (CS, section 9.2.4)
* The certificates MAY include the policy OID `2.23.140.1.4.1` to assert
  compliance with the CS requirements (CS, section 9.3.1)
* The Key Usage extension MUST be present and MUST be marked critical; the
  `digitalSignature` bit MUST be set, the bits `keyCertSign` and `cRLSign` MUST
  NOT be set and other positions SHOULD NOT be set (CS, appendix B)
* The Extended Key Usage MUST include `id-kp-codeSigning`; `documentSigning` and
  `emailProtection` MAY be present; `anyExtendedKeyUsage` and `serverAuth` MUST
  NOT be present; other values SHOULD NOT be present (if they are present, the
  CA MUST have an agreement in place with a software vendor requiring that value
  in order to issue a platform-specific code signing certificate) (CS,
  appendix B)
* The private key MUST be stored on a TPM (in that case, the private key
  protection MUST be attested), a hardware crypto module conforming at least to
  FIPS 140 Level 2/Common Criteria EAL 4+ (or equivalent) or an SD card/USB
  form factor token that is not necessarily FIPS certified (in that case, the
  token MUST be kept in use only when one or more signing operations are in
  progress); the first two options are preferred (CS, section 16.3)

## Extended Validation code signing
* In the Subject Distinguished Name, the `commonName` MUST be present and MUST
  contain the subject's legal name (EVCS, section 9.2.3)
* In the Subject Distinguished Name, the `organizationName` field is required
  and can be at most 64 characters long; an assumed name/DBA MAY be used, as
  long as it is followed by the full organization name in parenthesis. If the
  field contents would exceed 64 characters, the CA MAY abbreviate parts of the
  organization name and/or omit non-material words; if it is not possible to do
  so, the CA MUST NOT issue the certificate (EV, section 9.2.1; EVCS, section
  9.2.1)
* In the Subject Distinguished Name, the `businessCategory` field is required
  and MUST contain `Private Organization`, `Government Entity`,
  `Business Entity` or `Non-Commercial Entity` depending on the entity type
  (EV, section 9.2.4; EVCS, section 9.2.4)
* In the Subject Distinguished Name, the `jurisdictionLocalityName`,
  `jurisdictionStateOrProvinceName` and `jurisdictionCountryName` are required
  (if the incorporating/registration agency is at the country level, only
  `jurisdictionCountryName` is required; if the agency is at the state/province
  level, both `jurisdictionCountryName` and `jurisdictionStateOrProvinceName`
  are required; if the agency is at the locality level, all mentioned fields are
  required). The country information MUST be specified using the applicable
  ISO country code; the locality and state/province information MUST be
  specified using the full name (EV, section 9.2.5; EVCS, section 9.2.5)
* In the Subject Distinguished Name, the `serialNumber` field is required; it
  MUST contain the registration number or, in case no such number is issued,
  the registration date in a commonly-recognized format (for private
  organizations or business entities) or appropriate language to indicate that
  the subject is a government entity (for government entities (EV, section
  9.2.6; EVCS, section 9.2.6)
* In the Subject Distinguished Name, the `localityName`, `stateOrProvinceName`
  and `countryName` are required; the `streetAddress` and `postalCode` fields
  are optional (EV, section 9.2.7; EVCS, section 9.2.7)
* In the Subject Distinguished Name, attributes MUST include only data verified
  by the CA and MUST NOT include metadata indicating that a field is absent or
  incomplete (EVCS, section 9.2.8)
* Each certificate MUST contain a policy identifier OID that is either the
  CA/Browser Forum EV identifier or an OID that marks the certificate as being
  an EV certificate; the policy qualifier ID MUST be `id-qt 1` and the `cPSuri`
  MUST be an HTTP URL pointing to the subordinate CA CPS (EV, sections 9.3.2
  and 9.7; EVCS, section 9.3)
* An EV code signing certificate MUST NOT be valid for more than 39 months;
  an EV code signing certificate issued to a signing authority/time stamp
  authority MUST NOT be valid for more than 135 months (EVCS, section 9.4)
* If no OCSP responder location is stored in the certificate, the
  `cRLDistributionPoint` extension MUST be present (EV, section 9.7)
* The Key Usage MUST be present, MUST be critical and MUST have the
  `digitalSignature` bit set; other bits SHOULD NOT be set (EVCS, section 9.7)
* The Extended Key Usage MUST be present and `id-kp-codeSigning` MUST be
  present; other usages SHOULD NOT be present (EVCS, section 9.7)
* EV certificates MUST be submitted to at least two CT logs (three for
  certificates valid for at least 15 and at most 27 months), at least one of
  which MUST be Google-operated and at least another MUST not; the SCTs must
  either be embedded in the certificate or presented via a TLS extension /
  embedded in a stapled OCSP response (CTC)

## Qualified certificates
**Note: this profile is based only on the ETSI TS 101 862 standard. Each EU
member state might impose additional requirements.**

* The subject DN SHALL be specified using the `domainComponent`, `countryName`,
  `commonName`, `surname`, `givenName`, `pseudonym`, `serialNumber`, `title`,
  `organizationName`, `organizationalUnitName`, `stateOrProvinceName` and
  `localityName` components; other attributes MAY be present. At least one of
  `commonName`, `givenName` and `pseudonym` SHALL be present. The `countryName`
  attribute value specifies a general context in which other attributes are to
  be understood. The `commonName` attribute SHALL contain a name of the
  subject; the `surname` and `givenName` attributes SHALL be used if neither
  `commonName` nor `pseudonym` are present (in case the subject has only a
  given name, `surname` SHALL be omitted); `pseudonym` SHALL, if present,
  contain a pseudonym of the subject (in case it is present, `surname` and
  `givenName` MUST NOT be present). `serialNumber` SHALL, if present, be used
  to discriminate between subjects which would have the same DN otherwise; it
  MAY be a CA- or government-issued identifier. The `title` attribute SHALL be
  used, if present, to store a role the subject has at the named organization.
  The `organizationName`/`organizationalUnitName` attributes SHALL be used, if
  present, to store the name/information about the organization with which the
  subject is associated. The `stateOrProvinceName` and `localityName`
  attributes SHALL be used, if present, to store the location with which the
  subject is associated; if `organizationName` is also present, those values
  MUST be associated with the location of the organization (RFC 3739,
  section 3.1.2)
* If the Subject Alternative Name extension is present and it contains a
  `directoryName`, its DN must be encoded following the rules specified for the
  subject DN (RFC 3739, section 3.2.1)
* The `subjectDirectoryAttributes` MAY be present and contain additional
  information about the subject; if present, it MUST NOT be critical. The
  following attributes SHALL be supported (each of them MAY be present):

    Attribute name         | Contents
    -----------------------|---------
    `dateOfBirth`          | The date of birth of the subject, specified as a `generalizedTime`: the time part should be `GMT 12.00.00`
    `placeOfBirth`         | The place of birth of the subject
    `gender`               | The gender of the subject (`F`/`f` or `M`/`m`)
    `countryOfCitizenship` | The identifier of at least one country of citizenship of the subject (multiple countries SHALL be specified by including each one in a separate attribute)
    `countryOfResidence`   | The identifier of at least one country of residence of the subject (multiple countries SHALL be specified by including each one in a separate attribute)

    (RFC 3739, section 3.2.2)

* The Certificate Policies extension SHALL be present and SHALL contain at
  least the identifier of one certificate policy; it MAY be critical. All
  policies required for certification path validation MUST be included; if
  policy related statements are included in the QCStatements extension, these
  statements SHOULD also be contained in the identifier policies. Policies MAY
  be combined with any qualifier defined in RFC 3280 (RFC 3739, section 3.2.3)
* The Key Usage extension SHALL be present and SHALL be set in accordance with
  RFC 3280: it SHOULD be critical (RFC 3739, section 3.2.4)
* Certificates MAY include a biometric information extension containing a
  hash of the information, a machine-readable description of it and a HTTP or
  HTTPS URI referencing a file containing the information (RFC 3739, section
  3.2.5)
* Certificates MAY include statements defining some explicit properties; each
  one SHALL include an OID and MAY include optional qualifying data (the syntax
  and semantics of which SHALL be defined by the OID). The
  `id-qcs-pkixQCSyntax-v1` statement MUST NOT be included (RFC 3739, section
  3.2.6)
* Qualified certificates SHALL include a statement extension with an
  `esi4-qcStatement-1` statement (ETSI TS 101 862, section 5.3)

## Time stamping certificate
* The Key Usage extension MUST be present and MUST be marked critical; the
  `digitalSignature` bit MUST be set; the `keyCertSign` and `cRLSign` bits MUST
  NOT be set; other bit positions SHOULD NOT be set (CS, appendix B)
* The Extended Key Usage MUST be critical and MUST include `id-kp-timeStamping`;
  `anyExtendedKeyUsage` MUST NOT be present; other values SHOULD NOT be present
  (if they are present, the CA MUST have an agreement in place with a software
  vendor requiring that value in order to issue a platform-specific code
  signing certificate) (CS, appendix B)
* The certificate used to sign timestamps MUST NOT be used for any other
  purpose and have a critical Extended Key Usage extension with the value
  `id-kp-timeStamping` (RFC 3161, sections 2.1 and 2.3)
* If a certificate is not to be used anymore, it SHOULD be revoked with the
  reason `unspecified`, `affiliationChanged`, `superseded` or
  `cessationOfOperation` (if the private key was not compromised) or
  `keyCompromise` (if the private key was compromised) (RFC 3161, section 4)
* The key length MUST be sufficiently long to allow for a long lifetime
  (RFC 3161, section 4)
* The certificate MUST have a maximum validity period of 135 months; a keypair
  MUST NOT be used for more than 15 months (CS, section 9.4)
* A RFC 3161 compatible responder MUST be provided (CS, section 16.1)
* The signing key MUST be protected by a FIPS 140-2 Level 3, Common Criteria
  EAL 4+ or higher certified process (CS, section 16.1)
* The digest algorithm used to sign timestamp tokens MUST match the one used
  to sign the time stamping certificate (CS, appendix A)

## OCSP responder certificates
* OCSP responses should be signed either by the CA that issued the certificate
  to check or using a dedicated certificate, issued by that CA, having an
  Extended Key Usage extension that includes `id-kp-OCSPSigning` as a value
  (RFC 6960, section 4.2.2.2, and BR, section 4.9.9)
* If a dedicated certificate is used, it MUST include a non-critical extension
  `id-pkix-ocsp-nocheck` with a `NULL` value (to specify that no revocation
  checking should be performed on that certificate); for this reason, in this
  case, the certificate lifetime should be short (RFC 6960, section 4.2.2.2.1,
  and BR, section 4.9.9)

## CRL profiles and OCSP notes
* The CRL version MUST be v2; the CRL itself MUST include the `nextUpdate`
  field, the CRL number and the Authority Key Identifier (RFC 5280, sections 5
  and 5.2.1)
* The CRL signing algorithm should be one of those listed in RFC 3279 or its
  updates (RFC 4055, RFC 4491, RFC 5480, RFC 5756, RFC 5758) for maximum
  compatibility (each software implementation that conforms to RFC5280 MUST
  support them); other algorithms can be used (RFC 5280, section 5.1.1.2)
* If the Issuer Alternative Name is present, it MUST be non critical (RFC 5280,
  section 5.2.2)
* The CRL number MUST be non-critical, monotonically increasing and at most 20
  octets long (RFC 5280, section 5.2.3)
* The Authority Information Access extension MUST be non-critical, MUST include
  at least one `id-ad-caIssuers` entry and SHOULD specify at least one HTTP or
  LDAP access location; HTTP URIs MUST point to a single DER-encoded
  certificate served with the MIME type `application/pkix-cert` (or a
  collection of certificates) (RFC 5280, section 5.2.7)
* CRLs of CAs that directly issue end entity certificates MUST be issued at
  least once every seven days, and the `nextUpdate` field in the CRL MUST NOT
  be more than ten days beyond the value of the `thisUpdate` field; CRLs of CAs
  that only issue subordinate CA certificates MUST be issued at least once
  every twelve months (or within 24 hours of the revocation of a subordinate
  CA), and the `nextUpdate` field in the CRL MUST NOT be more than twelve months
  beyond the value of the `thisUpdate` field (BR, section 4.9.7)
* CRLs of end entity certificates MUST be issued at least once every seven
  days (for time stamping certificates, the CRL MUST be issued at most 24 hours
  after a certificate is revoked) and the `nextUpdate` field in the CRL MUST NOT
  be more than ten days beyond the value of the `thisUpdate` field. The
  revocation information MUST be published via OCSP at most every four days (if
  a subordinate time stamping CA certificate is revoked, at most within 24
  hours from revocation), the responses MUST have a maximum expiration time of
  ten days and the value in the nextUpdate field MUST be before or equal to the
  `notAfter` date of all certificates included within the
  `BasicOCSPResponse.certs` field or, if the `certs` field is omitted, before
  or equal to the notAfter date of the CA certificate which issued the
  certificate that the `BasicOCSPResponse` is for (CS, section 13.2.2; MSRP,
  section 6)
* In case the CA issues server authentication certificates, the revocation
  information MUST be published via OCSP; the validity must range from eight
  hours to seven days and the next update must be made available at least eight
  hours before the expiration time or (if the validity is more than 16 hours)
  at one half of the validity period (MTRPR, section 4.C.3)
* OCSP responders SHALL support the `GET` method (CS, section 13.2.2)
* OCSP responders SHOULD listen on port 80 and SHOULD NOT operate over HTTPS
  (MCARP, section "OCSP")
* OCSP responses SHOULD have a maximum validity period of one day (MTRPR,
  section 5.4)
