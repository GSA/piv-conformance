# piv-conformance
Tool for testing the PIV card data model. Its existing test cases derive from SP 800-85B guidance; selected checks have been updated for FIPS 201-3, SP 800-73-5 Part 1, SP 800-78-5, and SP 800-76-2. A passing run does not establish complete coverage of those publications.

## Build status

The current source build requires Java 17. Build from the repository root in this order:

```sh
cd cardlib && ./gradlew check install && cd ..
cd conformancelib && ./gradlew check install && cd ..
cd tools/85b-swing-gui && ./gradlew test shadowJar
```

The GUI JAR is written to `tools/85b-swing-gui/build/libs/`. The older Windows build page in `docs/README.md` is historical.

## Unreleased flat-ZIP candidate

With a Java 17 JDK in `JAVA_HOME` and `zip` installed, run `./doit.sh` from the repository root. It builds and tests Cardlib, Conformancelib and the GUI, then writes a flat ZIP and its SHA-256 under `build/releases/`. Extract the complete ZIP; use `run.bat` on Windows or `run.sh` on macOS/Linux with Java 17 on `PATH`. The included `README.txt` gives the run and results locations. The ZIP is a candidate until its extracted Windows/card workflow is validated.

The packaged `x509-certs/cacerts.jks` is the exact 174-entry external trust store from the published [v1.0.9 release](https://github.com/GSA/piv-conformance/releases/tag/v1.0.9), whose ZIP SHA-256 is `2f5b82458b6c058c94eabb060ba1a9ad5e2610f777a1be3cdf87731496a656cb`. The JKS SHA-256 is `41496e64cb241c8f98bebee33ff2f1f98530d4febc2ab0b9d369910578628a10`; `doit.sh` checks it before packaging. Trust policy and existing per-user overrides need review before a public release.

## References ##

### FIPS Publications ###
- [FIPS 140 Federal Information Processing Standards Publication FIPS 140-2, Security Requirements for
Cryptographic Modules](https://doi.org/10.6028/NIST.FIPS.140-2)
- [FIPS 201-3 Personal Identity Verification (PIV) of Federal Employees and Contractors](https://doi.org/10.6028/NIST.FIPS.201-3)

### ISO/IEC Publications ###
- ISO/IEC 17043, Conformity assessment – General requirements for proficiency testing, 2010
- ISO/IEC 10373 Identification Cards—Test Methods. Part 1—Standard for General Characteristic Test of Identification Cards, ISO, 1998. Part 3—Standard for Integrated Circuit Cards with Contacts and Related Interface Devices, ISO, 2001. Part 6—Standard for Proximity Card Support in Identification Cards, ISO, 2001
- ISO/IEC 7816, Identification Cards—Integrated Circuits with Contacts, Parts 1-6, ISO
- ISO/IEC 14443-1:2000, Identification Cards—Contactless Integrated Circuit(s) Cards—Proximity Cards, ISO, 2000

### NIST Special Publications ###
- [SP 800-73-5 Part 1, PIV Card Application Namespace, Data Model and Representation](https://doi.org/10.6028/NIST.SP.800-73pt1-5)
- [SP800-76 Biometric Specifications for Personal Identity Verification](https://doi.org/10.6028/NIST.SP.800-76-2)
- [SP 800-78-5 Cryptographic Algorithms and Key Sizes for Personal Identity Verification](https://doi.org/10.6028/NIST.SP.800-78-5)
- [SP800-85A PIV Card Application and Middleware Interface Test Guidelines (SP 800-73-4 Compliance)](https://doi.org/10.6028/NIST.SP.800-85A-4)
- [SP800-85B PIV Data Model Test Guidelines (DRAFT)](https://csrc.nist.gov/CSRC/media/Publications/sp/800-85b/4/draft/documents/sp800_85b-4_draft.pdf)
- [SP800-96 PIV Card to Reader Interoperability Guidelines](https://doi.org/10.6028/NIST.SP.800-96)
- [SP800-116 A Recommendation for the Use of PIV Credentials in Physical Access Control Systems (PACS)](https://doi.org/10.6028/NIST.SP.800-116)

### RFCs ###
- [RFC 3370 Cryptographic Message Syntax (CMS) Algorithms](https://tools.ietf.org/html/rfc3370)
- [RFC 3447 Public-Key Cryptography Standards (PKCS) #1: RSA 1233 Cryptography Specifications Version 2.1](https://tools.ietf.org/html/rfc3447)
- [RFC 4122 A Universally Unique IDentifier (UUID) URN Namespace](https://tools.ietf.org/html/rfc4122)
- [RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://www.ietf.org/rfc/rfc5280.txt)
- [RFC 5480 Elliptic Curve Cryptography Subject Public Key Information](https://tools.ietf.org/html/rfc5480)
- [RFC 5652 Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
- [RFC 5754 Using SHA2 Algorithms with Cryptographic Message Syntax](https://tools.ietf.org/html/rfc5754)
- [RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc6960)

### Other Publications, Memoranda, or Documents ###
- [HSPD-12 Policy for a Common Identification Standard for Federal Employees and Contractors, August 2004](http://www.dhs.gov/homeland-security-presidential-directive-12)
- [OMB 11-11 Mandatory Use of Personal Identity Verification (PIV) Credentials](https://www.whitehouse.gov/sites/whitehouse.gov/files/omb/memoranda/2011/m11-11.pdf)
- [X.509 Certificate Policy For The U.S. Federal PKI Common Policy Framework](http://www.idmanagement.gov/fpki-x509-cert-policy-common/)
- [X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for the Shared Service Providers (SSP) Program](https://www.idmanagement.gov/fpki-cert-profile-ssp/)
- [Certificate Policy for the Federal Bridge Certification Authority (FBCA)](https://www.idmanagement.gov/fpki-x509-cert-policy-fbca/)
- [PIV Interoperability for Issuers (PIV-I)](https://www.idmanagement.gov/piv-i-for-issuers/)