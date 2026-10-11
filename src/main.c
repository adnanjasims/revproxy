#include "server.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    rp_config_t cfg;
    rp_server_t srv;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: revproxy <config>\n");
        return 2;
    }
    if (rp_config_load(argv[1], &cfg) != 0) {
        return 1;
    }
    if (rp_server_init(&srv, &cfg) != 0) {
        return 1;
    }
    rc = rp_server_run(&srv);
    rp_server_shutdown(&srv);
    return rc == 0 ? 0 : 1;
}
