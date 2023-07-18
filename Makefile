BUILD_DIR=./build
LIBEXP_DIR=./libexp

DOCKER=docker run
DOCKERFLAGS=--security-opt seccomp=./seccomp.json --rm -it
DOCKERMOUNTS=-v $(shell pwd):/io
DOCKERIMAGE=corjail

INCLUDES_DIR=-I $(LIBEXP_DIR)
CCWARN=-Wall -Weverything -Werror
CCNOWARN=-Wno-padded -Wno-reserved-id-macro -Wno-unused-macros -Wno-format-nonliteral -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression -Wno-gnu-auto-type -Wno-c++98-compat
CCFLAGS=$(CCWARN) $(CCNOWARN) $(INCLUDES_DIR) -pthread -O3 -std=gnu11 -fPIC
LDFLAGS=-lkeyutils
CC=clang

LIBEXP_MODULES=sched_stuff.o xattr.o heap_defragment.o poll_stuff.o heap_spray.o key_stuff.o rop.o tsfence.o utils.o rw_pipe_and_tty.o tty_write_stuff.o leaks.o errhandling.o
SOURCE_FILES=libexp/* sploit.{c,h} config.h

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

ifeq ($(A_INFER),1)
	INFER = /inc.langfer/bin/infer
	INFERDIR = $(HOME)/.local/src/infer/docker/master/infer-host
	DOCKERMOUNTS+=-v $(INFERDIR):/infer
	CC := $(INFER) capture -r -- $(CC)
endif
DOCKERIZE=$(DOCKER) $(DOCKERFLAGS) $(DOCKERMOUNTS) $(DOCKERIMAGE)

.PHONY: clean build_dir all

all: _sploit _test_privesc

build_dir:
	$(call msg,MKDIR,$(BUILD_DIR))
	$(Q)mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(LIBEXP_DIR)/$(notdir %).c $(wildcard $(LIBEXP_DIR)/*.h) config.h | build_dir
	$(call msg,MODULE,$(subst .o,,$(notdir $@)))
	$(Q)$(DOCKERIZE) $(CC) $(CCFLAGS) -c -o $@ $<

%.a: $(addprefix $(BUILD_DIR)/,$(LIBEXP_MODULES))
	$(call msg,LIBRARY,$(subst .a,,$(notdir $@)))
	$(Q)ar rcs $@ $^

_%: %.c %.h $(BUILD_DIR)/libexp.a
	$(call msg,BINARY,$(@:_%=%))
	$(Q)$(DOCKERIZE) $(CC) $(CCFLAGS) $(CCFLAGSEXTRA) $(LDFLAGS) -o $(BUILD_DIR)/$(@:_%=%) $< $(BUILD_DIR)/libexp.a

clean:
	$(call msg,CLEAN,)
	$(Q)rm -rf sploit test_privesc $(BUILD_DIR)

cppcheck:
	cppcheck \
		--cppcheck-build-dir=cppcheck-build-dir \
		-I $(INCLUDES_DIR) \
		--platform=unix64 \
		$(SOURCE_FILES)

semgrep:
	semgrep scan \
		--config auto \
		--config p/c \
		--config p/gitlab \
		--config p/security-audit \
		--config p/r2c-security-audit \
		$(SOURCE_FILES)
