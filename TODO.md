# Items TODO

## Project
0. Document how to use this script for application code
1. Refactor to separate config from execution
2. Determine how to unit test the code
3. Better model who writes to config files happen. Flush/sync at close?
4. Use a pid file to prevent concurrent mods of config?
5. Move default config building out of script
6. Replace 'saml-i' with saml-<random> to avoid order based assumptions
7. Consider not replacing existing kerberos_sts if they are not near expiration
8. Consider a purge flag to remove previously prompted values
9. Rename the project to be less specific to kerberos, and split up kerberos and NTLM authentication?
