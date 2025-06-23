diffasn1
  Compare tsr.bin

tsr_compact_namer
  <$1 : fichier horodaté
  <$2 : fichier tsr
  >${BASE}_t:${SERIAL}_${SIGHASH}_$(date -d"$TIMESTAMP" -Is).$EXT
