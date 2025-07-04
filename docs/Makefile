MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(MAKE_RESTARTED),)
MAKE_RESTARTED := yes
export MAKE_RESTARTED

# redémarre make depuis le bon répertoire
default:
	exec $(MAKE) -C $(MAKEFILE_DIR) --no-print-directory $(MAKECMDGOALS)

# empêche l'exécution du reste
override MAKECMDGOALS :=
endif

fr/sealgood.md : ../bin/sealgood
	tail -n +2 "$<" > "$@" && git add "$@"
