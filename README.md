# OpenSSL CA templates
This repository contains several OpenSSL CA templates for a two-tiered
Certification Authority.

**This work is in an alpha stage!** A test suite that uses [certlint](https://github.com/awslabs/certlint)
to validate the generated certificates is being worked on (we are hitting some
edge cases we need to cross-check). For now, use these templates at your own
risk.

## Generation instructions
1. Open the configuration files and edit them where the comments ask you to do
   so.
2. Generate the root CA by running the following commands:

    ```
    mkdir -p root{,/newcerts}
    echo 01 >root/crlserial
    echo 01 >root/serial
    touch root/index{,.attr}
    ROOTCASERIAL=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1)
    openssl req -config openssl_root_ca.cnf -x509 -newkey rsa:4096 -sha256 -keyout root/rootca.pvk -out root/rootca.cer -days 3650 -set_serial 0x$ROOTCASERIAL -extensions root_ca_extensions
    openssl x509 -in root/rootca.cer -out root/rootca_der.cer -outform DER
    ```

3. Generate the intermediate CAs you need by editing the `distinguished_name`
   setting in `openssl_root_ca.cnf` and running the following commands:

    ```
    mkdir -p CANAME{,/newcerts}
    echo 01 >CANAME/crlserial
    echo 01 >CANAME/serial
    touch CANAME/index{,.attr}
    openssl req -config openssl_root_ca.cnf -new -newkey rsa:4096 -sha256 -keyout CANAME/CANAMEca.pvk -out CANAME/CANAMEca.req
    cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1 >root/serial
    # Note: manually check that the serial is not already assigned to another certificate in root/index
    openssl ca -config openssl_root_ca.cnf -in CANAME/CANAMEca.req -out CANAME/CANAMEca.cer -policy root_ca_dn_policy -extensions CAEXTENSIONS
    openssl x509 -in CANAME/CANAMEca.cer -out CANAME/CANAMEca_der.cer -outform DER
    ```

    Replace `CANAME` and `CAEXTENSIONS` as follows:

    | For the following CA type...                       | use this `CANAME`...                | and these `CAEXTENSIONS`                                    |
    |----------------------------------------------------|-------------------------------------|-------------------------------------------------------------|
    | Personal certificates, e-mail validation           | `personal-emailvalidated`           | `personal-emailvalidated_ca_certificate_extensions`         |
    | Personal certificates, individual validation       | `personal-individualvalidated`      | `personal-individualvalidated_ca_certificate_extensions`    |
    | Personal certificates, organization validation     | `personal-organizationvalidated`    | `personal-organizationvalidated_ca_certificate_extensions`  |
    | Web server certificates, domain validation         | `webserver-domainvalidated`         | `webserver-domainvalidated_ca_certificate_extensions`       |
    | Web server certificates, individual validation     | `webserver-individualvalidated`     | `webserver-individualvalidated_ca_certificate_extensions`   |
    | Web server certificates, organization validation   | `webserver-organizationvalidated`   | `webserver-organizationvalidated_ca_certificate_extensions` |
    | Web server certificates, Extended Validation       | `webserver-extendedvalidation`      | `webserver-extendedvalidation_ca_certificate_extensions`    |
    | Code signing certificates, individual validation   | `codesigning-individualvalidated`   | `codesigning_ca_certificate_extensions`                     |
    | Code signing certificates, organization validation | `codesigning-organizationvalidated` | `codesigning_ca_certificate_extensions`                     |
    | Code signing certificates, Extended Validation     | `codesigning-extendedvalidation`    | `codesigning-extendedvalidation_ca_certificate_extensions`  |
    | Time stamping certificates                         | `timestamping`                      | `timestamping_ca_certificate_extensions`                    |
    | Time stamping certificates, Extended Validation    | `timestamping-extendedvalidation`   | `timestamping_ca_certificate_extensions`                    |

3. Generate the certificates you need by running the following commands:

    ```
    openssl req -config CAFILE -new -newkey rsa:4096 -sha256 -keyout PVKPATH.pvk -out REQPATH.req
    cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1 >CANAME/serial
    # Note: manually check that the serial is not already assigned to another certificate in CANAME/index
    openssl ca -config CAFILE -name CANAME_ca -in REQPATH.req -out CERPATH.cer -subj 'SUBJECTDN'
    # Optionally export the newly generated certificate to a PKCS12 file:
    openssl pkcs12 -export -out PKCS12PATH.p12 -in CERPATH.cer -inkey PVKPATH.pvk -name "FRIENDLYNAME" -certfile CANAME/CANAMEca.cer -caname "FRIENDLYCANAME"
    ```

    Perform the following replacements:

    | Variable         | Value                                                                                                                                                                                                                            |
    |------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
    | `CAFILE`         | The `.cnf` file containing the configuration for the CA you are using                                                                                                                                                            |
    | `PVKPATH`        | The path to the private key file you are generating                                                                                                                                                                              |
    | `REQPATH`        | The path to the certificate request file you are generating                                                                                                                                                                      |
    | `CERPATH`        | The path to the certificate file you are generating                                                                                                                                                                              |
    | `PKCS12PATH`     | The path to the .p12 file you are generating                                                                                                                                                                                     |
    | `CANAME`         | The CA name, see step 2                                                                                                                                                                                                          |
    | `SUBJECTDN`      | The DN of the subject you are issuing the certificate to, e.g. `/C=IT/O=Sample Organization/CN=Sample Subject`. See the policy sections in each `.cnf` file for the DN fields you will need to include for each certificate type |
    | `FRIENDLYNAME`   | The "friendly name" for the certificate subject (usually, the CN field of the DN)                                                                                                                                                |
    | `FRIENDLYCANAME` | The "friendly name" for the CA certificate subject (usually, the CN field of the DN)                                                                                                                                             |
