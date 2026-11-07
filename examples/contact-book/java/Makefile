# contact-book example in Java
#
# Generates Java from ../contact.asn1 (--target=java), compiles it with the
# java-runtime sources and Main.java using plain javac, and runs it.
#
# Usage:
#   make          build classes/
#   make run      build and run (writes /tmp/contact.ber, prints XER)
#   make test     run and diff against contact.expected (same output as the C++ example)
#   make clean    remove all generated/built output

ASN1CPP_ROOT ?= ../../..
ASNCPP       ?= $(ASN1CPP_ROOT)/build/compiler/asn1cpp
JAVAC        ?= javac
JAVA         ?= java

RUNTIME_SRC  := $(ASN1CPP_ROOT)/java-runtime/src/main/java
GEN_DIR      := gen
CLASSES      := classes
STAMP        := $(CLASSES)/.stamp

all: $(STAMP)

$(GEN_DIR)/.stamp: ../contact.asn1 $(ASNCPP)
	rm -rf $(GEN_DIR) && mkdir -p $(GEN_DIR)
	$(ASNCPP) --target=java --package=contacts --remove-stale ../contact.asn1 -o $(GEN_DIR)/contacts
	touch $@

$(STAMP): $(GEN_DIR)/.stamp Main.java $(shell find $(RUNTIME_SRC) -name '*.java')
	rm -rf $(CLASSES) && mkdir -p $(CLASSES)
	find $(RUNTIME_SRC) $(GEN_DIR) -name '*.java' > $(CLASSES)/sources.txt
	echo Main.java >> $(CLASSES)/sources.txt
	$(JAVAC) --release 21 -nowarn -d $(CLASSES) @$(CLASSES)/sources.txt
	touch $@

run: $(STAMP)
	$(JAVA) -cp $(CLASSES) Main

test: $(STAMP)
	$(JAVA) -cp $(CLASSES) Main contact.ber > actual.txt
	diff contact.expected actual.txt
	@echo "contact-book (Java): output matches"

clean:
	rm -rf $(GEN_DIR) $(CLASSES) contact.ber actual.txt

.PHONY: all run test clean
