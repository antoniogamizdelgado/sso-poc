# Single Sign On: You Shall Not Password (Again)

Hello! This repository contains several examples of SSO workflows.

## SAML 2.0

What you need to have ready to give to customers asking for SSO:

- Entity ID
- ACS
- Public certificates (if using signed SAML requests)

For SAML2.0, we offer to workflows:

- Adhoc: without using any third party library
- Third party: using `pysaml2`

Both should work with the same app on the IdP. To switch between the implementations, just modify the `if` statement at the end of `server.py` file.

### Security comments

This proof of concept **does not implement all security considerations** we need to follow. Some of the missing ones are described [here](https://infosec.mozilla.org/guidelines/iam/saml.html).