# piv-conformance
Tool for testing the PIV card data model. Its case catalog derives from SP 800-85B guidance. Version `2.0.0` updates selected checks for FIPS 201-3, SP 800-73-5 Part 1, and SP 800-78-5, and corrects selected checks under SP 800-76-2. A passing run does not establish complete coverage of those publications or certify a card. [Issue #332](https://github.com/GSA/piv-conformance/issues/332) records the delivered updates and remaining work.

## How the checks are organized

The four profile databases describe cases and select which Java JUnit test method (an *atom*) runs, with the card object and any parameters it needs. The assertion itself is Java code in `conformancelib`; `cardlib` decodes card data, and the GUI runs the selected cases and reports their results. The catalog sources include profile workbooks, SQL dumps, and SQLite databases. For example, PIV case 8.1.8 now routes to an atom that rejects CCC tags E3 and B4. This release covers selected SP 800-73-5 Part 1 changes to CCC, CHUID, and active certificate containers; it has not completed an exhaustive Part 1 requirements audit. PIV-I retains historical routes where applicability has not been established.

## Run CCT

The [user guide](docs/USER_GUIDE.md) covers running CCT, viewing results, preparing a lab submission and diagnostics.

For Windows clients, choose the **Windows x64 ZIP** on the [releases page](https://github.com/GSA/piv-conformance/releases). Use **Extract All**, then open **`CCT.exe`**. Java is included. Keep the extracted `app` and `runtime` directories beside the launcher.

The **portable ZIP (Java 17 required)** retains `run.bat` for Windows and `run.sh` for macOS/Linux. Its launchers use Java 17 on `PATH`. **Source code (zip / tar.gz)** are equivalent source snapshots for developers and require a build. See [build instructions](docs/README.md). Public downloads do not require a GitHub account.

Optional [download verification](docs/USER_GUIDE.md#verify-the-download-optional) compares the ZIP's SHA-256 with the published value.

In the GUI, choose the **PIV** or **PIV-I** toolbar button (or **File → Open Database** for another `.db` profile). Insert the card, click **Refresh Readers**, select its reader, and check **Reader Status**. Enter the PIV application PIN in the GUI and click **Verify PIN and Execute Tests**. After the run completes, use **View Test Results** to open the **Results** tab inside CCT, or **Package Results** to create a ZIP for that run. The **Testing** tab returns to the existing card workflow.

The Results tab appears after a run and updates for each new run. Select a summary card or filter to review **Pass**, **Fail** and **Unsupported** cases. Details show the recorded cause, available expected/observed values and the selected profile's expected outcome. Profiles can specify an expected Fail for a negative case; execution errors also retain the Fail label.

**Unsupported** means the check is not implemented or needs evidence CCT does not have, such as vendor values or original fingerprint images. It does not by itself mean card data is missing. The tests have no separate Warning or Caution result.

Source cards separate **Official wording (excerpt)** from **What CCT checks**. Available excerpts are stored with the result; links open the official document online. **Copy finding** and the packaged summary include these references. See the [results guide](docs/USER_GUIDE.md#viewing-test-results) for details.

Logs and result packages are written under the per-user CCT data directory: `%LOCALAPPDATA%\GSA\CCT` on Windows, `~/Library/Application Support/GSA/CCT` on macOS, and `$XDG_DATA_HOME/GSA/CCT` (or `~/.local/share/GSA/CCT` when unset) on Linux. Packages are under its `runs` directory and include the selected database, the completed run's logs and artifacts, the `x509-certs` files used for validation, and a readable `*-results-summary.txt` with counts and case details requiring review. The summary is included even if Results was never opened. The package completion dialog offers **Show in Folder**, **Copy Path**, **View Results** and **Done**. CCT preserves an existing per-user `x509-certs/cacerts.jks`, which takes precedence over the copy in the ZIP; review and back up customized trust material before replacing it.

## Build status

The current source build requires Java 17. Build from the repository root in this order:

```sh
cd cardlib && ./gradlew check install && cd ..
cd conformancelib && ./gradlew check install && cd ..
cd tools/85b-swing-gui && ./gradlew test shadowJar
```

The GUI JAR is written to `tools/85b-swing-gui/build/libs/`. See the [build notes](docs/README.md) for Windows module commands and the `CCT_GIT_COMMIT` / `CCT_GIT_COMMIT_EPOCH` metadata needed when building an extracted source archive without Git history.

## Portable ZIP build

With a Java 17 JDK in `JAVA_HOME`, use a Bash environment with `zip` and `shasum` and run `./doit.sh` from the repository root. It builds and tests Cardlib, Conformancelib and the GUI, then writes a flat ZIP and its SHA-256 under `build/releases/`. Extract the complete ZIP; use `run.bat` on Windows or `run.sh` on macOS/Linux with Java 17 on `PATH`. The included `README.txt` and `USER_GUIDE.md` give the run and results instructions. Both packages remain candidates until their extracted native/card workflows are validated.

The packaged `x509-certs/cacerts.jks` is the exact 174-entry external trust store from the published [v1.0.9 release](https://github.com/GSA/piv-conformance/releases/tag/v1.0.9), whose ZIP SHA-256 is `2f5b82458b6c058c94eabb060ba1a9ad5e2610f777a1be3cdf87731496a656cb`. The JKS SHA-256 is `41496e64cb241c8f98bebee33ff2f1f98530d4febc2ab0b9d369910578628a10`; `doit.sh` checks it before packaging.

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
- [SP 800-85B PIV Data Model Test Guidelines (final, 2006)](https://csrc.nist.gov/pubs/sp/800/85/b/final). The later [SP 800-85B-4 draft](https://csrc.nist.gov/pubs/sp/800/85/b/4/ipd) was discontinued; its case lineage is historical guidance, not a final current standard.
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
