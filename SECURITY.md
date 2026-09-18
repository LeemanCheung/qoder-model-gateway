# Security boundary

This project is a local-only gateway. Do not bind it to a LAN or public address, reverse proxy it, share its local API key, or commit files from the user state directory.

The intended Qoder authentication path is read-only. Renew a Qoder login with the official Qoder client or CLI. Do not open an issue containing a credential, local gateway key, model cache, request capture, private endpoint, or session transcript.

For a potential vulnerability, create a private GitHub security advisory for this repository or contact the repository owner privately with a minimal reproduction that contains no secrets.
