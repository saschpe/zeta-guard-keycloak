<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PDP

## Release 0.3.2

> [!IMPORTANT]  
> The source code for this release relies on a [patched version of Keycloak](https://github.com/techatspree/keycloak), which is not yet merged into the main Keycloak repository. To build this project from source code, you will need to clone the patched Keycloak repository and build it locally using the special version tag '999.0.0-SNAPSHOT' first. 

### changed:
- update release notes

## Release 0.3.1

### changed:
- update release notes 

## Release 0.3.0

### added:
- verification of client's software attestation (currently behind environment variable-based toggle CHECK_CLIENT_ATTESTATION_ENABLED -> do not touch for production, this toggle will be removed in the future)
- client-statement is read from client assertion JWT
- refresh token expiry is now determined by opa policies

### changed:
- more lenient OID verification for SMCB, so that all SMCBs can be used
- improved test coverage measurement

## Release 0.2.4

### added:
- mapping userdata and clientdata into access token
- more consistent license headers via maven plugin

### changed:
- minor updates and improvements

## Release 0.2.3

### changed:
- minor compliance-specific code formatting changes

## Release 0.2.2

### added:
- SBOM generation

## Release 0.2.1

### changed:
- refactoring smc-b keystore for unit tests

## Release 0.2.0

### added:
- SMC-B token exchange
- storage of user and client data
- client registration according to spec
- nonce endpoint
- ZETA-specific discovery endpoint
- OPA integration for access tokens in token exchange

## Release 0.1.2

### added:
- Prototype of the ZETA PDP added
