```console
[1;36mSealGood - Document signing and timestamping via OpenSSL + TSA[0m

Usage: sealgood help genkey { clean date sign verify }

COMMANDS:
  genkey    Generate a new password-protected ed25519 key pair
  help      Show this help
  clean     Extract original content without SEALGOOD tags
  date      Timestamp a document via trusted third party (TSA)
  sign      Sign a document with your private key
  verify    Verify document signature and timestamp

  Commands compose into an implicitly ordered pipeline:

  clean | sign | date | verify
  - reads data from stdin
  - comments progress on stderr
  - writes data to stdout
  - does NEVER write/modify any file directly

  Whenever input is a file list, the list is enumerated
  and each item is streamed to the processing pipeline.
  The output is packaged in tar+gzip format with cryptographic
  hashes embedded in signed/timestamped filenames
  enumerate
   \
     +-- clean | sign | date | verify

  sign date       respect existing signature/timestamp;
  enumerate sign  asks private key passphrase only once.

Examples:
  sealgood sign date < contract.pdf > contract_sealgood.pdf
  sealgood verify    < contract_sealgood.pdf
  ls contract*.pdf | sealgood sign date > contracts.tgz

Files used:
  $HOME/.ssh/ed25519_private_*.pem  : signer private keys
  $HOME/.ssh/ed25519_public_*.pem   : associated public keys
  $HOME/.ssh/id_rsa.pub             : signer identity declaration
  https://freetsa.org/files/cacert.pem : TSA root certificate

Free servlet :
  ssh -o SendEnv=LANGUAGE sealgood@perso.tlp.name {clean date verify}

See also : https://github.com/tibolpol/sealgood

Copyright (c) 2025 Thibault Le Paul (@tibolpol)
Licence MIT - https://opensource.org/license/mit/
[1;32mmain output: application/x-empty; charset=binary[0m
```
