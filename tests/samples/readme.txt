!../integration/test_basic
!../integration/test_aa
!../unit/test_lookup
!../unit/test_extract

!3</dev/null fdtty=3 sealgood clean verify <~/.ssh/ed25519_public_*sealgood:*.pem
!3</dev/null fdtty=3 sealgood       verify <~/.ssh/ed25519_public_*sealgood:*.pem

!sealgood clean < readme.txt
!sealgood clean < pempub
!sealgood date  < pempub

!ls test_date_{es,fr} | LANG=en            sealgood date >/dev/null
!ls test_date_{es,us} | STOPFILE=/stopfile sealgood date

# verify : un membre n'apparaît pas en sortie, compression ??
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood verify | tar  -zxf- --to-command='wc -'
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood verify | tar  -zxf- --to-command='diff ${TAR_FILENAME:1:13} -'
# il est dans l'index
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood verify | tar  -ztf-

# clean : ok
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood clean  | tar  -zxf- --to-command='wc -'
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood clean  | tar  -zxf- --to-command='diff pempub -'
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood clean  | tar  -ztf-

!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | tar -ztf-
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | zcat | strings -n12 -weS
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood verify      <pubkeys.tgz >/dev/null #| zcat | strings -n12 -weS
!sealgood verify < pubkeys.tgz >/dev/null
!fddebug=2 sealgood date < pubkeys.tgz >/dev/null
!tar -ztf pubkeys.tgz

