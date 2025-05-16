# 🦭 Trust Me Seal 🦭
Generate CA-signed certificates for an IP for use with C-Lodop local print servers.

## How to run
`./trustmeseal.exe --dns [IP] --passphrase [PASSWORD]`

Example:
`./trustmeseal.exe --dns 192.168.1.1 --passphrase password123`
Both IP and passphrase are required. Please remember the passphrase used as you will need it when you install the certificates on Windows hosts. Make sure the IP is a _static_ IP that is being used by the PC running the C-Lodop print server.

## Installing certificates
Certificates will need to be installed on all PCs that will run the key-in order page.

The C-Lodop print server settings will also need to be updated. 

Detailed instructions to come soon! 🦭