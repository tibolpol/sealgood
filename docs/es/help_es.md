```console
[1;36mSealGood - Firma y sellado temporal de documentos mediante OpenSSL + TSA[0m

Uso: sealgood help genkey { clean date sign verify }

COMANDOS:
  genkey    Genera un nuevo par de claves ed25519 protegido por contraseña
  help      Mostrar esta ayuda
  clean     Extraer contenido original sin etiquetas SEALGOOD
  date      Sellar temporalmente un documento mediante tercero de confianza (TSA)
  sign      Firmar un documento con tu clave privada
  verify    Verificar firma y sello temporal del documento

  Los comandos forman un pipeline ordenado implícitamente:

  clean | sign | date | verify
  - lee datos desde stdin
  - comenta progreso en stderr
  - escribe datos en stdout
  - NUNCA escribe/modifica ningún archivo directamente

  Cuando la entrada es una lista de archivos, esta se enumera
  y cada elemento se procesa en el pipeline de transformación.
  El resultado se empaqueta en formato tar+gzip con hashes criptográficos
  incrustados en nombres de archivo firmados/marcados temporalmente
  enumerate
   \
     +-- clean | sign | date | verify

  sign date       respeta firma/sello temporal existente;
  enumerate sign  solicita frase de contraseña de clave privada solo una vez.

Ejemplos:
  sealgood sign date < contract.pdf > contract_sealgood.pdf
  sealgood verify    < contract_sealgood.pdf
  ls contract*.pdf | sealgood sign date > contracts.tgz

Archivos utilizados:
  $HOME/.ssh/ed25519_private_*.pem  : claves privadas del firmante
  $HOME/.ssh/ed25519_public_*.pem   : claves públicas asociadas
  $HOME/.ssh/id_rsa.pub             : declaración de identidad del firmante
  https://freetsa.org/files/cacert.pem : certificado raíz TSA

Servlet gratuita :
  ssh -o SendEnv=LANGUAGE sealgood@perso.tlp.name {clean date verify}

Ver también : https://github.com/tibolpol/sealgood

Copyright (c) 2025 Thibault Le Paul (@tibolpol)
Licence MIT - https://opensource.org/license/mit/
[1;32mmain output: application/x-empty; charset=binary[0m
```
