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

clean:
	rm -f $(PROGRAM) $(PROGRAM).d

.PHONY: clean

-include $(PROGRAM).d
