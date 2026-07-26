# contact-book example
#
# Generates C++ from contact.asn1, compiles the generated types and main.cpp,
# and links against the asn1cpp runtime.
#
# Usage:
#   make          build the example binary (contact-book)
#   make run      build and run (writes /tmp/contact.ber, prints XER)
#   make clean    remove all generated/built output

ASNCPP      := ../../build/compiler/asn1cpp
RUNTIME_INC := ../../runtime/include
RUNTIME_LIB := ../../build/runtime/libasn1cpp_runtime.a

ASN1_FILE   := contact.asn1
GEN_DIR     := gen
OBJ_DIR     := obj
BINARY      := contact-book

CXX         := g++
CXXFLAGS    := -std=c++20 -O2 -Wall -I$(GEN_DIR) -I$(RUNTIME_INC)

# ---------------------------------------------------------------------------
# Phase 1 — code generation
# ---------------------------------------------------------------------------

$(GEN_DIR)/sources.mk: $(ASN1_FILE) $(ASNCPP)
	@mkdir -p $(GEN_DIR) $(OBJ_DIR)
	$(ASNCPP) $(ASN1_FILE) -o $(GEN_DIR)
	@ls $(GEN_DIR)/*.cpp | tr '\n' ' ' | sed 's/^/GEN_SRCS := /' > $@

-include $(GEN_DIR)/sources.mk

# ---------------------------------------------------------------------------
# Phase 2 — compile generated types + main.cpp
# ---------------------------------------------------------------------------

$(OBJ_DIR):
	mkdir -p $@

OBJ_FILES := $(patsubst $(GEN_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(GEN_SRCS)) $(OBJ_DIR)/main.o

$(OBJ_DIR)/%.o: $(GEN_DIR)/%.cpp | $(GEN_DIR)/sources.mk $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/main.o: main.cpp | $(GEN_DIR)/sources.mk $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# ---------------------------------------------------------------------------
# Phase 3 — link
# ---------------------------------------------------------------------------

$(BINARY): $(OBJ_FILES) $(RUNTIME_LIB)
	$(CXX) -o $@ $^

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

all: $(BINARY)

run: $(BINARY)
	./$(BINARY)

# gambas-asn1#299: best-effort --target=rust build of the book-tutorial
# schema — smaller/faster companion probe to the ETSI one, and covers
# OPTIONAL members / nested SEQUENCE / SEQUENCE OF (contact.asn1 uses all
# three), none of which RustBackend's table-driven SEQUENCE emission
# supports yet. Expected to fail; not wired into ctest/CI.
RUST_PROBE_DIR := rust-probe
RUST_PROBE_SRC := $(RUST_PROBE_DIR)/src

rust-probe: $(ASN1_FILE) $(ASNCPP)
	@rm -rf $(RUST_PROBE_SRC)
	@mkdir -p $(RUST_PROBE_SRC)
	$(ASNCPP) $(ASN1_FILE) --target=rust -o $(RUST_PROBE_SRC)
	@echo "[GEN]  $$(ls $(RUST_PROBE_SRC)/*.rs | wc -l) .rs files written"
	@echo "[CARGO] building $(RUST_PROBE_DIR) ..."
	-cd $(RUST_PROBE_DIR) && cargo build 2>&1 | tee build.log
	@echo "[REPORT] $$(grep -c '^error' $(RUST_PROBE_DIR)/build.log || echo 0) compile errors, $$(grep -c '^warning:' $(RUST_PROBE_DIR)/build.log || echo 0) warnings"

clean:
	rm -rf $(GEN_DIR) $(OBJ_DIR) $(BINARY)

clean-rust-probe:
	rm -rf $(RUST_PROBE_SRC) $(RUST_PROBE_DIR)/target $(RUST_PROBE_DIR)/Cargo.lock $(RUST_PROBE_DIR)/build.log

.PHONY: all run clean rust-probe clean-rust-probe
