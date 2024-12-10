/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * Modified by: George Theodorakis <csd4881@csd.uoc.gr>
 * Modified by: Kalliopi Nefeli Sfakianaki <csd5516@csd.uoc.gr>
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

#include "microtcp_utils.h"

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
        socket && address && socket->state != INVALID &&
        "Something was not initialized or was invalid" &&
        "Invalid checks should fail because we never create somethin invalid");

    if (bind(socket->sd, address, address_len) == -1) return -1;

    socket->state = LISTEN;
    return 0;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
    /* If something is not initialized we can return -1 */
    assert(
        socket && address && socket->state != INVALID &&
        "Something was not initialized or was invalid" &&
        "Invalid checks should fail because we never create somethin invalid");

    microtcp_header_t connect_header =
        NEW_CONNECT_HEADER(socket->seq_number, socket->ack_number);
    connect_header.checksum =
        crc32((uint8_t *)&connect_header, sizeof(microtcp_header_t));

    if (sendto(socket->sd, &connect_header, sizeof(microtcp_header_t), 0,
               address, address_len) == -1) {
        return -1;
    }

    microtcp_header_t receive_header = {0};
    if (recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                 MSG_WAITALL, (struct sockaddr *)address, &address_len) == -1) {
        return -1;
    }

    uint32_t checksum = receive_header.checksum;

    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    if (checksum != receive_header.checksum ||
        receive_header.control != ACCEPT_CTRL) {
        return -1;
    }

    socket->ack_number = connect_header.seq_number + 1;
    socket->seq_number = receive_header.ack_number;

    connect_header.ack_number = receive_header.seq_number + 1;
    connect_header.seq_number = receive_header.ack_number;

    connect_header.control = ACK_BIT;
    connect_header.checksum = 0;
    connect_header.checksum =
        crc32((uint8_t *)&connect_header, sizeof(microtcp_header_t));

    if (sendto(socket->sd, &connect_header, sizeof(microtcp_header_t), 0,
               address, address_len) == -1) {
        return -1;
    }

    socket->state = ESTABLISHED;

    return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    /* If something is not initialized we can return -1 */
    assert(
        socket && address && socket->state != INVALID &&
        "Something was not initialized or was invalid" &&
        "Invalid checks should fail because we never create somethin invalid");

    microtcp_header_t receive_header = {0};
    if (recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                 MSG_WAITALL, (struct sockaddr *)address, &address_len) == -1) {
        return -1;
    }

    uint32_t checksum = receive_header.checksum;

    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    if (checksum != receive_header.checksum ||
        receive_header.control != CONNECT_CTRL) {
        return -1;
    }

    socket->ack_number = receive_header.seq_number + 1;
    microtcp_header_t accept_header =
        NEW_ACCEPT_HEADER(socket->seq_number, socket->ack_number);

    accept_header.checksum =
        crc32((uint8_t *)&accept_header, sizeof(microtcp_header_t));
    if (sendto(socket->sd, &accept_header, sizeof(microtcp_header_t), 0,
               address, address_len) == -1) {
        return -1;
    }

    if (recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                 MSG_WAITALL, (struct sockaddr *)address, &address_len) == -1) {
        return -1;
    }

    checksum = receive_header.checksum;
    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    if (checksum != receive_header.checksum ||
        receive_header.control != ACK_BIT) {
        return -1;
    }

    socket->ack_number = receive_header.seq_number + 1;
    socket->seq_number = receive_header.ack_number;

    socket->state = ESTABLISHED;

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
