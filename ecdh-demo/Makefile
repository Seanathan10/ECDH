CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic
LDLIBS   = -lcrypto
TARGET   = ecdh

ifeq ($(shell uname), Darwin)
	OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
	ifneq ($(OPENSSL_PREFIX),)
		CFLAGS  += -I$(OPENSSL_PREFIX)/include
		LDFLAGS += -L$(OPENSSL_PREFIX)/lib
	endif
endif

.PHONY: all clean help

all: $(TARGET)

$(TARGET): ecdh.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	@echo
	@echo "Built ./$(TARGET) -> run it as:  ./$(TARGET)"

clean:
	rm -f $(TARGET)

help:
	@echo "make          build ./$(TARGET)"
	@echo "make clean    removes the binary, leaving only the code"
	@echo "make help     prints this help message"
	@echo
	@echo "Needs the OpenSSL development headers (1.1.1 or newer):"
	@echo "  Debian/Ubuntu   sudo apt install build-essential libssl-dev"
	@echo "  macOS           xcode-select --install && brew install openssl@3"
	@echo "  Fedora/RHEL     sudo dnf install gcc openssl-devel"
	@echo "  Arch            sudo pacman -S base-devel openssl"
