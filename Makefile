BEND ?= bend

.PHONY: bootstrap check test e2e build clean

bootstrap:
	./scripts/bootstrap.sh

check:
	@for file in main.bend src/*.bend src/merkle/*.bend tests/*.bend; do \
		BEND_NO_TELEMETRY=1 $(BEND) $$file --check-only >/dev/null || exit 1; \
	done

test: check
	BEND=$(BEND) ./scripts/test.sh

build: check
	BEND_NO_TELEMETRY=1 $(BEND) main.bend -o bend-client

e2e: bootstrap build
	./tests/e2e.sh

clean:
	rm -f bend-client bend-client.c bend-client.js bend-client.mjs bend-client.gpu
