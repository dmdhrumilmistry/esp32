# Builds the portable firmware modules for the host (needs libmbedtls-dev).
ROOT    := ../..
FW      := $(ROOT)/firmware/main
WG      := $(ROOT)/firmware/components/esp_wireguard/src
CFLAGS  ?= -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter -fsanitize=address,undefined
CPPFLAGS := -I$(FW) -I$(WG)

p2p_host: p2p_host.c $(FW)/p2p_crypto.c $(FW)/p2p_stun.c $(FW)/p2p_portmap_proto.c $(WG)/crypto/refc/x25519.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Wno-error=stringop-overread -o $@ $^ -lmbedcrypto

clean:
	rm -f p2p_host

.PHONY: clean
