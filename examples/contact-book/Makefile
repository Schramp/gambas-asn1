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

clean:
	rm -rf $(GEN_DIR) $(OBJ_DIR) $(BINARY)

.PHONY: all run clean
