# asn1cpp ETSI LI PS-PDU example
#
# Generates C++ from all ETSI ASN.1 schemas, compiles them into a static
# library, and exposes headers via include/ and the archive via lib/.
#
# Usage:
#   make            build library (uses -j automatically for compilation)
#   make -j 8       explicit parallelism
#   make clean      remove all generated/built output
#
# Outputs consumed by audio-cpp (and other tools):
#   include/        generated .hpp files (all type headers)
#   lib/libasn1cpp_etsi.a
#   runtime headers: ../../runtime/include  (add to your -I as well)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ASNCPP      := ../../build/compiler/asn1cpp
RUNTIME_INC := ../../runtime/include

ASN1_DIR  := asn1-files
GEN_DIR   := gen
OBJ_DIR   := obj
LIB_DIR   := lib
INC_DIR   := include
LIBRARY   := $(LIB_DIR)/libasn1cpp_etsi.a

ASNCPP_FLAGS := -fallow-newer-modules -pdu=PS-PDU -pdu=EncryptedPayload

# ---------------------------------------------------------------------------
# Source discovery (all .asn and .asn1 files under asn1-files/)
# ---------------------------------------------------------------------------

ASN_FILES := $(shell find $(ASN1_DIR) \( -name "*.asn" -o -name "*.asn1" \) | sort)

# ---------------------------------------------------------------------------
# Compiler settings
# ---------------------------------------------------------------------------

CXX      := g++
AR       := ar

# Precompiled header for asn1cpp.hpp — parses ~87k lines once, reused by all TUs.
# Use -include approach: GCC looks for pch.hpp.gch alongside the -include'd file.
PCH_DIR     := $(OBJ_DIR)/pch
PCH_WRAP    := $(PCH_DIR)/pch.hpp
PCH_GCH     := $(PCH_WRAP).gch
OPT        ?= -O3 -flto=auto
BASE_FLAGS  := -std=c++20 $(OPT) -I$(GEN_DIR) -I$(RUNTIME_INC)
# -MMD -MP: emit a .d file per .o recording every header it #included (runtime
# headers in particular). Without this, make has no way to know a .o is stale
# after a runtime header changes — only its own .cpp's mtime is tracked, so a
# stale .a can silently link against a newer runtime and produce an ODR
# mismatch (see gambas-asn1 #207).
CXXFLAGS    := $(BASE_FLAGS) -include $(PCH_WRAP) -MMD -MP

.DEFAULT_GOAL := all

$(PCH_WRAP): | $(OBJ_DIR)
	@mkdir -p $(PCH_DIR)
	@printf '#include <memory>\n#include <optional>\n#include <vector>\n#include <span>\n#include <string>\n#include <cstdint>\n#include <asn1cpp/asn1cpp_gen.hpp>\n' > $@

$(PCH_GCH): $(PCH_WRAP) $(RUNTIME_INC)/asn1cpp/asn1cpp_gen.hpp $(wildcard $(RUNTIME_INC)/asn1cpp/*.hpp)
	@echo "[PCH]  asn1cpp_gen.hpp"
	$(CXX) $(BASE_FLAGS) -x c++-header -o $@ $<

# Declare all before any other target so it is the default goal.
all: $(LIBRARY)

# ---------------------------------------------------------------------------
# Phase 1 — code generation
#
# gen/sources.mk is built by running asn1cpp over all ASN.1 files.
# It defines GEN_SRCS (the list of generated .cpp files).
# GNU make re-reads the Makefile after building an -include'd file, so the
# first `make` invocation both generates and compiles in one go.
# ---------------------------------------------------------------------------

$(OBJ_DIR):
	mkdir -p $@

$(GEN_DIR)/sources.mk: $(ASN_FILES) $(ASNCPP)
	@echo "[GEN]  running asn1cpp on $(words $(ASN_FILES)) ASN.1 files ..."
	@mkdir -p $(GEN_DIR) $(OBJ_DIR) $(LIB_DIR)
	$(ASNCPP) $(ASN_FILES) $(ASNCPP_FLAGS) -o $(GEN_DIR) 2>&1 | grep -v '^warning:'
	@ls $(GEN_DIR)/*.cpp | tr '\n' ' ' | sed 's/^/GEN_SRCS := /' > $@
	@echo "[GEN]  $$(ls $(GEN_DIR)/*.cpp | wc -l) .cpp files written"
	@ln -sfn ../$(GEN_DIR) $(INC_DIR)

-include $(GEN_DIR)/sources.mk

# ---------------------------------------------------------------------------
# Phase 2 — parallel compilation (.cpp → .o)
# ---------------------------------------------------------------------------

OBJ_FILES := $(patsubst $(GEN_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(GEN_SRCS))

$(OBJ_DIR)/%.o: $(GEN_DIR)/%.cpp $(PCH_GCH) | $(GEN_DIR)/sources.mk
	@echo "[CXX]  $(<F)"
	@ulimit -s unlimited && $(CXX) $(CXXFLAGS) -c -o $@ $<

# Pull in the per-.o header dependency files generated above (-MMD -MP), so a
# runtime header change correctly marks the affected .o (and hence $(LIBRARY))
# stale on the next plain `make` — no `regen`/`clean` needed for header-only edits.
-include $(OBJ_FILES:.o=.d)

# ---------------------------------------------------------------------------
# Phase 3 — archive
# ---------------------------------------------------------------------------

$(LIBRARY): $(OBJ_FILES) | $(LIB_DIR)
	@echo "[AR]   $@ ($(words $^) objects)"
	$(AR) rcs $@ $^

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

regen:
	rm -f $(GEN_DIR)/sources.mk
	$(MAKE) $(GEN_DIR)/sources.mk

# gambas-asn1#299: best-effort --target=rust build of the real ETSI LI
# PS-PDU schema — the credibility probe for the Rust backend (#214/#220).
# Expected to fail until #300-#305 (and further construct-coverage issues)
# land; NOT wired into ctest/CI, run on demand to check progress.
# rust-probe/src/ is regenerated fresh every run (rm -rf first: asn1cpp
# deletes stale files from a previous run of its own invocation, but never
# a stale prior --target=rust run using a different flag set).
RUST_PROBE_DIR := rust-probe
RUST_PROBE_SRC := $(RUST_PROBE_DIR)/src

rust-probe: $(ASN_FILES) $(ASNCPP)
	@echo "[GEN]  running asn1cpp --target=rust on $(words $(ASN_FILES)) ASN.1 files ..."
	@rm -rf $(RUST_PROBE_SRC)
	@mkdir -p $(RUST_PROBE_SRC)
	$(ASNCPP) $(ASN_FILES) $(ASNCPP_FLAGS) --target=rust -o $(RUST_PROBE_SRC)
	@echo "[GEN]  $$(ls $(RUST_PROBE_SRC)/*.rs | wc -l) .rs files written"
	@echo "[CARGO] building $(RUST_PROBE_DIR) ..."
	-cd $(RUST_PROBE_DIR) && cargo build 2>&1 | tee build.log
	@echo "[REPORT] $$(grep -c '^error' $(RUST_PROBE_DIR)/build.log || echo 0) compile errors, $$(grep -c '^warning:' $(RUST_PROBE_DIR)/build.log || echo 0) warnings"

clean:
	rm -rf $(GEN_DIR) $(OBJ_DIR) $(LIB_DIR) $(INC_DIR)

clean-rust-probe:
	rm -rf $(RUST_PROBE_SRC) $(RUST_PROBE_DIR)/target $(RUST_PROBE_DIR)/Cargo.lock $(RUST_PROBE_DIR)/build.log

.PHONY: all clean regen rust-probe clean-rust-probe
