
default : fr/sealgood.md fr/help_fr.md pt/help_pt.md us/help_us.md es/help_es.md

fr/sealgood.md : ../bin/sealgood
	tail -n +2 "$<" > "$@" && git add "$@"

us/help_us.md : ../bin/sealgood
	(echo '```console'; LANGUAGE=us "$<" help 2>&1; echo '```' ) >"$@"

fr/help_fr.md : ../bin/sealgood ../locale/fr/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=fr "$<" help 2>&1; echo '```' ) >"$@"

pt/help_pt.md : ../bin/sealgood ../locale/pt/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=pt "$<" help 2>&1; echo '```' ) >"$@"

es/help_es.md : ../bin/sealgood ../locale/es/LC_MESSAGES/sealgood.mo
	(echo '```console'; LANGUAGE=es "$<" help 2>&1; echo '```' ) >"$@"

../locale/es/LC_MESSAGES/sealgood.mo : ../locale/es/LC_MESSAGES/sealgood.po
	cd es/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po

../locale/fr/LC_MESSAGES/sealgood.mo : ../locale/fr/LC_MESSAGES/sealgood.po
	cd fr/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po

../locale/pt/LC_MESSAGES/sealgood.mo : ../locale/pt/LC_MESSAGES/sealgood.po
	cd pt/LC_MESSAGES&& msgfmt -o sealgood.mo sealgood.po
