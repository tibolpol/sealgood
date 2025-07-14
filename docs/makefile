
default : fr/sealgood.md fr/filetypes.md fr/help_fr.md pt/help_pt.md us/help_us.md es/help_es.md \
../locale/es/LC_MESSAGES/sealgood.mo ../locale/pt/LC_MESSAGES/sealgood.mo \
../tests/integration/test_basic.stdout

# vues markdown pour github
fr/filetypes.md : ../bin/filetypes
	tail -n +2 "$<" > "$@" && git add "$@"

fr/sealgood.md : ../bin/sealgood
	tail -n +2 "$<" > "$@" && git add "$@"

# pages de help générées
us/help_us.md : ../bin/sealgood ../bin/filetypes
	(echo '```console'; LANGUAGE=us ../bin/sealgood help 2>&1; echo '```' ) >"$@"

fr/help_fr.md : ../bin/sealgood ../bin/filetypes ../locale/fr/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=fr ../bin/sealgood help 2>&1; echo '```' ) >"$@"

pt/help_pt.md : ../bin/sealgood ../bin/filetypes ../locale/pt/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=pt ../bin/sealgood help 2>&1; echo '```' ) >"$@"

es/help_es.md : ../bin/sealgood ../bin/filetypes ../locale/es/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=es ../bin/sealgood help 2>&1; echo '```' ) >"$@"

# locales
../locale/es/LC_MESSAGES/sealgood.mo : ../locale/es/LC_MESSAGES/sealgood.po
	cd es/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po

../locale/fr/LC_MESSAGES/sealgood.mo : ../locale/fr/LC_MESSAGES/sealgood.po
	cd fr/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po

../locale/pt/LC_MESSAGES/sealgood.mo : ../locale/pt/LC_MESSAGES/sealgood.po
	cd pt/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po

# signale lorsque les tests ne sont pas à jour
../tests/integration/test_basic.stdout \
../tests/integration/test_aa.stdout : ../bin/sealgood ../bin/filetypes \
../locale/es/LC_MESSAGES/sealgood.mo ../locale/fr/LC_MESSAGES/sealgood.mo ../locale/pt/LC_MESSAGES/sealgood.mo
	echo "KO test non effectué depuis les dernières modifications" >>"$@" && git add "$@"
