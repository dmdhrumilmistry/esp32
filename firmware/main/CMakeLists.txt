idf_component_register(
    SRCS "main.c"
         "p2p_config.c"
         "p2p_crypto.c"
         "p2p_stun.c"
         "p2p_portmap_proto.c"
         "p2p_portmap.c"
         "p2p_acl.c"
         "p2p_events.c"
         "p2p_tunnel.c"
         "p2p_signal.c"
         "p2p_auth.c"
         "p2p_web.c"
         "p2p_wifi.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "www/index.html"
    REQUIRES esp_wireguard esp_wifi esp_netif esp_event esp_http_server esp_timer
             nvs_flash mbedtls lwip json driver esp-tls bootloader_support)
