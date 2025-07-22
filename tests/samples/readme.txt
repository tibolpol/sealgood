!../integration/test_basic
!../integration/test_aa
!../unit/test_lookup
!../unit/test_extract

!tar -ztf pubkeys.tgz

!3</dev/null fdtty=3 sealgood clean verify <~/.ssh/ed25519_public_Thibault_LE_PAUL_sealgood:e037f239.pem
!3</dev/null fdtty=3 sealgood       verify <~/.ssh/ed25519_public_Thibault_LE_PAUL_sealgood:e037f239.pem

!sealgood clean < readme.txt
!sealgood clean < pempub
!sealgood date  < pempub

!while ((ii++<3));do ls test_date_{es,fr,pt,us};done | fddebug=2 sealgood date | tar  -zvxOf-
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do wc - <$ff;done >&2)| fddebug=2 sealgood verify | tar  -zxf- --to-command="wc -"
!while ((ii++<1));do ls test_date_{es,fr,pt,us};done | tee >(while read ff;do ssh sealgood@perso.tlp.name verify <$ff;done >&2)| fddebug=2 sealgood verify | tar  -zxf- --to-command="wc -"

!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | tar -ztf-
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood date verify <pubkeys.tgz | zcat | strings -n12 -weS
!3</dev/null fdtty=3 fddebug=2 LANGUAGE=us sealgood verify      <pubkeys.tgz >/dev/null #| zcat | strings -n12 -weS

!ls test_date_{fr,es,us,pt} | sort -R | LANGUAGE=fr STOPFILE=/stopfile sealgood date

!git log --oneline --decorate --graph --all
!git show





!cd tests/integration&&(while ((ii++<2));do ls ../samples/test_date_{es,fr,pt,us};done | fddebug=2 ../../bin/sealgood date | zcat | strings -n12 -weS)
!cd tests/integration&&(ls ../samples/test_date_{es,fr} | ../../bin/sealgood date >/dev/null)


!sealgood verify < pubkeys.tgz >/dev/null
!tar -ztf  pubkeys.tgz
!zcat pubkeys.tgz | strings -n12 -weS
!fddebug=2 sealgood date < pubkeys.tgz >/dev/null
