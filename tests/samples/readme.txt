!../integration/test_basic
!../integration/test_aa
!../integration/test_shellscript
!../unit/test_type ../samples/pempub "text/[PEM] Public key+plain; charset=utf-8"
!../unit/test_type ../samples/pubkeys.tgz "application/tar+gzip; charset=binary"
!../unit/test_type ../../bin/sealgood "text/x-shellscript; charset=utf-8"
!../unit/test_tsr64

!3</dev/null fdtty=3 sealgood clean verify <~/.ssh/ed25519_public_*sealgood:*.pem
!3</dev/null fdtty=3 sealgood       verify <~/.ssh/ed25519_public_*sealgood:*.pem

!sealgood clean < readme.txt
!sealgood clean < pempub
!sealgood date  < pempub

!ls test_date_{es,fr} | LANG=en            sealgood date >/dev/null
!ls test_date_{es,us} | STOPFILE=/stopfile sealgood date

# verify : le dernier membre n'apparaît pas en sortie
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | sort -R | tee /dev/stderr | 2>/dev/null fddebug=2 sealgood verify | tar  -zxf- --to-command='echo ${TAR_FILENAME%%_sealgood*}'
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | sort -R | tee /dev/stderr | 2>/dev/null fddebug=2 sealgood verify | tar  -ztf-

# date, clean : ok
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | sort -R | tee /dev/stderr | 2>/dev/null fddebug=2 sealgood date   | tar  -zxf- --to-command='echo ${TAR_FILENAME%%_sealgood*}'
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | sort -R | tee /dev/stderr | 2>/dev/null fddebug=2 sealgood clean  | tar  -zxf- --to-command='echo ${TAR_FILENAME%%_sealgood*}'

# alors qu'il est dans l'index
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2) | 2>/dev/null fddebug=2 sealgood verify | tar  -ztf-

# clean : ok

!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | tar -ztf-
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | zcat | strings -n12 -weS
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood verify      <pubkeys.tgz >/dev/null #| zcat | strings -n12 -weS
!sealgood verify < pubkeys.tgz >/dev/null
!fddebug=2 sealgood date < pubkeys.tgz >/dev/null
!tar -ztf pubkeys.tgz

