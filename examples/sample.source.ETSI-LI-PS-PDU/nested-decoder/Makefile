ASN1CPP_ROOT ?= ../../..

ETSI_DIR    := ..
ETSI_INC    := $(ETSI_DIR)/gen
ETSI_LIB    := $(ETSI_DIR)/lib/libasn1cpp_etsi.a
RUNTIME_INC := $(ASN1CPP_ROOT)/runtime/include
RUNTIME_LIB := $(ASN1CPP_ROOT)/build/runtime/libasn1cpp_runtime.a

CXX      := g++
OPT      ?= -O3
CXXFLAGS := -std=c++20 $(OPT) -MMD -MP -I$(ETSI_INC) -I$(RUNTIME_INC)
LIBS     := $(ETSI_LIB) $(RUNTIME_LIB)

PROGRAM  := nested-decoder

$(PROGRAM): nested-decoder.cpp $(ETSI_LIB) $(RUNTIME_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

# Random-filled regression input and its expected output (both committed;
# regenerate only on purpose, then review the .expected diff).
gen-testdata: gen-testdata.cpp $(ETSI_LIB) $(RUNTIME_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

testdata: gen-testdata $(PROGRAM)
	./gen-testdata pdu-00000001.etsi
	./$(PROGRAM) pdu-00000001.etsi > pdu-00000001.expected

clean:
	rm -f $(PROGRAM) $(PROGRAM).d gen-testdata gen-testdata.d

.PHONY: clean testdata

-include $(PROGRAM).d
