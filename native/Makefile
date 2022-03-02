# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))
PROJECT := $(subst -,_,$(PROJECT))

RUST_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so
SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.rs" \))

.DEFAULT_GOAL := $(RUST_SRC_OUTPUT)

$(RUST_SRC_OUTPUT): $(SOURCES)
	@mkdir -p $(BASEDIR)/priv/
	@cargo build --release
	@cp target/release/lib$(PROJECT).so $(RUST_SRC_OUTPUT)

clean:
	@cargo clean
	@rm -rf $(RUST_SRC_OUTPUT)