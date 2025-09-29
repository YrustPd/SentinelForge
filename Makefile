PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/sentinelforge

INSTALL_BIN = $(DESTDIR)$(BINDIR)/sentinelforge
INSTALL_SHARE = $(DESTDIR)$(SHAREDIR)

PHONY += install uninstall lint test clean

install:
	@echo "Installing SentinelForge into $(DESTDIR)$(PREFIX)"
	install -d $(DESTDIR)$(BINDIR)
	install -m750 bin/sentinelforge $(INSTALL_BIN)
	rm -rf $(INSTALL_SHARE)
	install -d $(INSTALL_SHARE)
	cp -R src $(INSTALL_SHARE)/
	cp -R etc $(INSTALL_SHARE)/
	cp -R share $(INSTALL_SHARE)/
	cp -R scripts $(INSTALL_SHARE)/
	cp VERSION $(INSTALL_SHARE)/
	cp README.md $(INSTALL_SHARE)/
	cp LICENSE $(INSTALL_SHARE)/

uninstall:
	rm -f $(INSTALL_BIN)
	rm -rf $(INSTALL_SHARE)

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck bin/sentinelforge scripts/*.sh; \
		find src -name '*.sh' -print0 | xargs -0 shellcheck; \
		echo 'shellcheck completed'; \
	else \
		echo 'shellcheck not installed; skipping'; \
	fi

test:
	@if command -v bats >/dev/null 2>&1; then \
		bats tests/bats; \
	else \
		echo "bats not installed; skipping"; \
	fi

clean:
	@echo "Nothing to clean"

.PHONY: $(PHONY)
