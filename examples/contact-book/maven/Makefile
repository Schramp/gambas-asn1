# contact-book example as a Maven project
#
# Publishes java-runtime into a private local Maven repository (as the
# released artifact io.github.schramp.gambasasn1:gambasasn1-wire would be
# resolved from Maven Central), then `mvn compile`: pom.xml runs asn1cpp on
# ../contact.asn1, requiring the runtime's version, and compiles the
# generated Java with ../java/Main.java. `make test` runs Main, then builds
# again from a copy of the generated code as if it were checked in
# (-Dasn1cpp.skip=true, no compiler on hand) and runs that too.
#
# Usage:
#   make          build target/classes
#   make test     run and diff against ../java/contact.expected
#   make clean    remove all generated/built output
#
# A released version: make test GAMBASASN1_VERSION=X.Y.Z SKIP_PUBLISH=1
# resolves it from Maven Central instead.

ASN1CPP_ROOT       ?= ../../..
ASNCPP             ?= $(ASN1CPP_ROOT)/build/compiler/asn1cpp
MVN                ?= mvn
JAVA               ?= java
GAMBASASN1_VERSION ?= 0.1.0-SNAPSHOT
REPO               := $(CURDIR)/m2
JAR                := $(REPO)/io/github/schramp/gambasasn1/gambasasn1-wire/$(GAMBASASN1_VERSION)/gambasasn1-wire-$(GAMBASASN1_VERSION).jar

all: target/.stamp

publish:
ifndef SKIP_PUBLISH
	$(ASN1CPP_ROOT)/java-runtime/gradlew -q -p $(ASN1CPP_ROOT)/java-runtime publishToMavenLocal \
		-Dmaven.repo.local=$(REPO) -Pversion=$(GAMBASASN1_VERSION)
endif

target/.stamp: ../contact.asn1 ../java/Main.java pom.xml $(ASNCPP) publish
	$(MVN) -q -B -Dmaven.repo.local=$(REPO) -Dgambasasn1.version=$(GAMBASASN1_VERSION) \
		-Dasn1cpp.executable=$(abspath $(ASNCPP)) compile
	touch $@

test: target/.stamp
	$(JAVA) -cp target/classes:$(JAR) Main contact.ber > actual.txt
	diff ../java/contact.expected actual.txt
	@echo "contact-book (Maven): output matches"
	rm -rf checked-in && cp -r target/generated-sources/asn1cpp checked-in
	$(MVN) -q -B -Dmaven.repo.local=$(REPO) -Dgambasasn1.version=$(GAMBASASN1_VERSION) \
		-Dasn1cpp.skip=true -Dasn1cpp.generated=$(CURDIR)/checked-in \
		-Dasn1cpp.executable=/nonexistent/asn1cpp \
		clean compile
	test ! -e target/generated-sources/asn1cpp
	$(JAVA) -cp target/classes:$(JAR) Main contact.ber > actual.txt
	diff ../java/contact.expected actual.txt
	@echo "contact-book (Maven, checked-in generated code): output matches"

clean:
	rm -rf target checked-in m2 contact.ber actual.txt

.PHONY: all publish test clean
