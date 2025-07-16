# Configuration
LANGUAGES := fr es pt
SCRIPTS   := ../bin/sealgood ../bin/filetypes
LOCALES   := $(foreach LANG,$(LANGUAGES),../locale/$(LANG)/LC_MESSAGES/sealgood.mo)
PGHELP    := $(foreach LANG,$(LANGUAGES),$(LANG)/help_$(LANG).md)
MARKDOWN  := fr/sealgood.md fr/filetypes.md
INTTEST   := ../tests/integration/test_basic.stdout ../tests/integration/test_aa.stdout

# Cible par défaut
.PHONY: default
default: $(LOCALES) $(MARKDOWN) $(PGHELP) us/help_us.md $(INTTEST)

# Règle pour les fichiers Markdown génériques
fr/%.md: ../bin/%
	tail -n +2 "$<" > "$@"

# Règle pour les fichiers d'aide (avec dépendance explicite des locales)
define HELP_RULE
$(1)/help_$(1).md: ../locale/$(1)/LC_MESSAGES/sealgood.mo $(SCRIPTS)
	(echo '```console'; LANGUAGE=$(1) ../bin/sealgood help </dev/null 2>&1; echo '```') > "$$@"
endef

$(foreach LANG,$(LANGUAGES),$(eval $(call HELP_RULE,$(LANG))))

# Règle spéciale pour l'anglais (us)
us/help_us.md: $(SCRIPTS)
	(echo '```console'; LANGUAGE=en ../bin/sealgood help </dev/null 2>&1; echo '```') > "$@"

# Règle pour les fichiers de traduction
../locale/%/LC_MESSAGES/sealgood.mo: ../locale/%/LC_MESSAGES/sealgood.po
	cd "$(@D)" && msgfmt -o sealgood.mo sealgood.po

# Règle pour les tests d'intégration
../tests/integration/test_%.stdout: $(SCRIPTS) $(LOCALES)
	echo "KO test non effectué depuis les dernières modifications" > "$@"

# Nettoyage
.PHONY: clean
clean:
	rm -f $(LOCALES) $(PGHELP) us/help_us.md $(MARKDOWN) $(INTTEST)
