# Java ETSI LI nested PS-PDU decoder — a port of ../nested-decoder.
#
# Generates Java from the ETSI LI schemas (with ../container_fields.json, so
# EncryptionContainer.encryptedPayload is decoded as an EncryptedPayload),
# compiles it together with the java-runtime sources using plain javac, and
# checks the output against the C++ decoder's committed regression output.
#
# CcOffsets.java, built alongside, prints the file byte range of every CC
# IP packet (IPCCContents.iPPackets) from decode positions and checks that
# the file holds the decoded packet there.
#
# The sample ../nested-decoder/pdu-00000001.etsi is synthetic: its field
# values, iPPackets included, are random filler from gen-testdata.cpp, so
# pdu-00000001.offsets.expected shows its one 5-octet packet as "not IPv4".
# CcOffsetsTest (tests/java) covers real IPv4 packets.
#
# Usage:
#   make          build classes/
#   make test     run on ../nested-decoder/pdu-00000001.etsi and diff the
#                 hex and inline XER forms against the committed .expected
#   make run IN=<file.etsi> [FORM=hex|inline|inline_raw]
#   make offsets IN=<file.etsi>   CC packet byte ranges
#   make clean

ASN1CPP_ROOT ?= ../../..
ASNCPP       ?= $(ASN1CPP_ROOT)/build/compiler/asn1cpp
JAVAC        ?= javac
JAVA         ?= java

ETSI_DIR     := ..
REF_DIR      := $(ETSI_DIR)/nested-decoder
RUNTIME_SRC  := $(ASN1CPP_ROOT)/java-runtime/src/main/java
ASN1_FILES   := $(sort $(shell find $(ETSI_DIR)/asn1-files -name '*.asn' -o -name '*.asn1'))
GEN_DIR      := gen
CLASSES      := classes
STAMP        := $(CLASSES)/.stamp

all: $(STAMP)

$(GEN_DIR)/.stamp: $(ASN1_FILES) $(ETSI_DIR)/container_fields.json $(ASNCPP)
	rm -rf $(GEN_DIR) && mkdir -p $(GEN_DIR)
	$(ASNCPP) --target=java --package=etsi -pdu=PS-PDU -pdu=EncryptedPayload \
	    -fallow-newer-modules --container-config=$(ETSI_DIR)/container_fields.json \
	    $(ASN1_FILES) -o $(GEN_DIR)/etsi
	touch $@

$(STAMP): $(GEN_DIR)/.stamp NestedDecoder.java CcOffsets.java $(shell find $(RUNTIME_SRC) -name '*.java')
	rm -rf $(CLASSES) && mkdir -p $(CLASSES)
	find $(RUNTIME_SRC) $(GEN_DIR) -name '*.java' > $(CLASSES)/sources.txt
	echo NestedDecoder.java >> $(CLASSES)/sources.txt
	echo CcOffsets.java >> $(CLASSES)/sources.txt
	$(JAVAC) --release 21 -nowarn -d $(CLASSES) @$(CLASSES)/sources.txt
	touch $@

FORM ?= hex
run: $(STAMP)
	$(JAVA) -cp $(CLASSES) NestedDecoder --xer-form $(FORM) $(IN)

offsets: $(STAMP)
	$(JAVA) -cp $(CLASSES) CcOffsets $(IN)

test: $(STAMP)
	$(JAVA) -cp $(CLASSES) NestedDecoder $(REF_DIR)/pdu-00000001.etsi > actual.xer
	diff $(REF_DIR)/pdu-00000001.expected actual.xer
	$(JAVA) -cp $(CLASSES) NestedDecoder --xer-form inline $(REF_DIR)/pdu-00000001.etsi > actual.inline.xer
	diff $(REF_DIR)/pdu-00000001.inline.expected actual.inline.xer
	@echo "java-nested-decoder: output matches the C++ nested-decoder"
	$(JAVA) -cp $(CLASSES) CcOffsets $(REF_DIR)/pdu-00000001.etsi > actual.offsets
	diff pdu-00000001.offsets.expected actual.offsets
	@echo "java-nested-decoder: CC packet offsets match"

clean:
	rm -rf $(GEN_DIR) $(CLASSES) actual.xer actual.inline.xer actual.offsets

.PHONY: all run offsets test clean
