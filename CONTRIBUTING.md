# Contribution guidelines
Please note that this project is released with a [Contributor Code of
Conduct](CONTRIBUTING.md). By participating in this project you agree to abide
by its terms.

## Style
* Files must be saved using the UTF-8 encoding, with no BOM and UNIX line
  terminators. OpenSSL configuration files must have a copyright header (see
  `openssl_root_ca.cnf` for an example).
* Follow the code style of existing configuration files.
* Use `example.com` for domains, `http://myca.example.com` for URLs, `My CA`
  as the `organizationName` of the CA and `IT` as the CA `countryName`.
* Additional OIDs should go in the `additional_oids` file.
* OIDs asserting compliance with CA/Browser Forum or CA store guidelines must
  not be included explicitly, but rather written as comments next to the row
  where they should go. This will prevent people that download the files and
  use them for internal CAs from asserting compliance, even when the validation
  practices they adopt differ from the ones mandated by the guidelines.

## Tests
* A test suite (which will be set up shortly) will automatically check the
  compliance of certificates generated using the profiles of this project with
  `cablint`. Your pull request should make the test suite pass.
* **Please note that making the test suite pass is not enough**. The checks
  performed by `cablint` at this time are less stringent than the ones mandated
  by the [Requirements summary](Requirements summary.md). You should still
  check your proposed modifications against the reference documents listed
  there.
