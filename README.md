# 🦭 Trust Me Seal 🦭

Generate CA-signed certificates for an IP for use with C-Lodop local print servers.

## How to run 🌊

`./trustmeseal.exe --dns [IP] --passphrase [PASSWORD]`

Example:

`./trustmeseal.exe --dns 192.168.1.1 --passphrase password123`

Both IP and passphrase are required. Please remember the passphrase used as you will need it when you install the certificates on Windows hosts. Make sure the IP is a _static_ IP that is being used by the PC running the C-Lodop print server.

## Installing certificates... 🌊

To get it working, you'll need to:
1. Set up C-Lodop to use OpenSSL
2. Install certificates on every key-in PC, or every PC that uses the printer

The browser may need to be restarted to see the effects.

All the certificates _must_ be the same -- if you want to change the certificates (eg: if the printer host's IP changes), you'll have to go through the whole process again -- certificate generation and installation. As these certificates are meant to be single-use only, it is best practice that you delete the previous certificates when you generate new ones. [See 'Deleting certificates' below.]

## ...on C-Lodop 🖨️

Go into system tray, right click on C-Lodop icon. Hover over 'Extended', select SSL(https) Option...

Navigate to the `output/printer` directory for each file and select the matching file. For the 'OpenSSL Key Password' field, type in the passphrase used at time of generating certificates.

## ...on Windows hosts 🪟

There are 2 ways to do this.

### CLI via Windows' `certutil` (requires Administrator access):

`certutil -user -f -p "password123" -importpfx "output\personal_certificate.p12"`

`certutil -user -f -p "password123" -importpfx "Root" "output\TRUSTED_ROOT.p12"`

### GUI (does not require Administrator access):

Navigate to the directory that `trustmeseal.exe` was run from, and go into `outputs/`. Double click to install `personal_certificate.p12`. When prompted for a password, enter the passphrase that was used for certificate generation. Leave everything else as default selections, and install.

Do the same for `TRUSTED_ROOT.p12`, however when selecting which certificate store, choose 'Place all certificates in the following store' and hit 'Browse'. Select 'Trusted Root Certification Authorities', then OK. Continue with the rest leaving default selections and install.

---

## Deleting certificates

Further instructions coming soon 🦭

## Assigning a static IP to the print server host

Assuming that the router is using DHCP and that you don't have access to the router's console...

A way (though less ideal) to have a sort-of static IP is to check if the router is only assigning DHCP IPs in a pool of IPs, then to choose an IP outside of the pool that isn't being used by another device.

Further instructions coming soon 🦭