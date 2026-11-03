# contact-book example as a Maven project
#
# Publishes java-runtime into a private local Maven repository (as the
# released artifact io.github.schramp.gambasasn1:gambasasn1-wire would be
# resolved from Maven Central), generates Java from ../contact.asn1,
# compiles it with Maven against that artifact, and runs ../java/Main.java.
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

src/.stamp: ../contact.asn1 ../java/Main.java $(ASNCPP)
	rm -rf src && mkdir -p src
	$(ASNCPP) --target=java --package=contacts ../contact.asn1 -o src/contacts
	cp ../java/Main.java src/
	touch $@

target/.stamp: src/.stamp pom.xml publish
	$(MVN) -q -B -Dmaven.repo.local=$(REPO) -Dgambasasn1.version=$(GAMBASASN1_VERSION) compile
	touch $@

test: target/.stamp
	$(JAVA) -cp target/classes:$(JAR) Main contact.ber > actual.txt
	diff ../java/contact.expected actual.txt
	@echo "contact-book (Maven): output matches"

clean:
	rm -rf src target m2 contact.ber actual.txt

.PHONY: all publish test clean
