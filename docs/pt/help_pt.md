```console
[1;36mSealGood - Assinatura e carimbo do tempo de documentos via OpenSSL + TSA[0m

Utilização: sealgood help genkey { clean date sign verify }

COMANDOS:
  genkey    Gerar um novo par de chaves ed25519 protegido por senha
  help      Mostrar esta ajuda
  clean     Extrair conteúdo original sem tags SEALGOOD
  date      Carimbar documento via terceira parte confiável (TSA)
  sign      Assinar documento com sua chave privada
  verify    Verificar assinatura e carimbo do tempo do documento

  Comandos compõem um pipeline implicitamente ordenado:

  clean | sign | date | verify
  - lê dados de stdin
  - comenta progresso em stderr
  - escreve dados em stdout
  - NUNCA escreve/modifica arquivos diretamente

  Quando entrada é lista de arquivos, a lista é enumerada
  e cada item é processado no pipeline.
  Saída é empacotada em formato tar+gzip com hashes
  criptográficos embutidos em nomes de arquivos assinados/carimbados
  enumerate
   \
     +-- clean | sign | date | verify

  sign date       respeita assinatura/carimbo existente;
  enumerate sign  pede senha da chave privada apenas uma vez.

Exemplos:
  sealgood sign date < contract.pdf > contract_sealgood.pdf
  sealgood verify    < contract_sealgood.pdf
  ls contract*.pdf | sealgood sign date > contracts.tgz

Arquivos utilizados:
  $HOME/.ssh/ed25519_private_*.pem  : chaves privadas do signatário
  $HOME/.ssh/ed25519_public_*.pem   : chaves públicas associadas
  $HOME/.ssh/id_rsa.pub             : declaração de identidade do signatário
  https://freetsa.org/files/cacert.pem : certificado raiz TSA

Servlet livre :
  ssh -o SendEnv=LANGUAGE sealgood@perso.tlp.name {clean date verify}

Veja também : https://github.com/tibolpol/sealgood

Copyright (c) 2025 Thibault Le Paul (@tibolpol)
Licence MIT - https://opensource.org/license/mit/
[1;32mmain output: application/x-empty; charset=binary[0m
```
