DIRS := $(patsubst %/,%,$(wildcard */))
#DIRS := ac_config dev_config dev_sta sgi client_call
DEV_CONFIG-y :=  one_click_conn plugin
#DEV_CONFIG-y :=  ac_config sgi client_call

export DEV_CONFIG_SRCDIR := $(CURDIR)

.PHONY: all
all: build

define compile_dirs
.PHONY: $(1)
$(1):
	@echo;echo "building $(1)..."
	$(MAKE) -C ${1}
endef

.PHONY: build
build: $(DEV_CONFIG-y)
${foreach dir,${DIRS},${eval ${call compile_dirs,${dir}}}}
