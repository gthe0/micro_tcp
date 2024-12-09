/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * Modified by: George Theodorakis <csd4881@csd.uoc.gr>
 * Modified by: Calliope Nepheli Sfakianaki <csd5516@csd.uoc.gr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"

#include <assert.h>
#include <crc32.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    microtcp_sock_t socket_obj;
    memset(&socket_obj, 0, sizeof(microtcp_sock_t));

    srand(time(NULL));
    socket_obj.seq_number = rand();

    if ((socket_obj.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Socket could not be opened.");
        exit(EXIT_FAILURE);
    }

    return (socket_obj);
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {

    /* If something is not initialized we can return -1 */
    assert(
        socket &&
        address &&
        socket->state != INVALID &&
        "Something was not initialized or invalid"
    );

    if(bind(socket->sd, address, address_len) == -1) return -1;

    socket->state = LISTEN;
    return 0;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
    return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) { return 0; }

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer,
                      size_t length, int flags) {
    return 0;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    return 0;
}
