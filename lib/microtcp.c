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
#include "microtcp_utils.h"

#include <crc32.h>

#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MIN(a,b) ((a) > (b) ? (b) : (a))

#define MICROTCP_HEADER_SZ       (sizeof(microtcp_header_t))
#define MICROTCP_DATA_CHUNK_SIZE ((MICROTCP_MSS) + (MICROTCP_HEADER_SZ))

// Socket Creation
microtcp_sock_t microtcp_socket(int domain, 
                                int type,
                                int protocol) {
    microtcp_sock_t socket_obj;
    int32_t optval = 1;

    memset(&socket_obj, 0, sizeof(microtcp_sock_t));
    srand(time(NULL));
    socket_obj.seq_number = rand();

    // Congestion control related stuff
    socket_obj.cwnd     = MICROTCP_INIT_CWND;
    socket_obj.ssthresh = MICROTCP_INIT_SSTHRESH;

    CHECK_ERROR_STMT((socket_obj.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) != MICROTCP_ERROR,
                     socket_obj.state = INVALID,
                     "Socket could not be opened.");

    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = MICROTCP_ACK_TIMEOUT_US
    };

    CHECK_ERROR_STMT((setsockopt(socket_obj.sd, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(struct timeval)) >= 0),,
                     "TimeInterval failed");

    CHECK_ERROR_STMT(setsockopt(socket_obj.sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) >= 0, 
                     socket_obj.state = INVALID, 
                     "Setting SO_REUSEADDR failed.");

    return (socket_obj);
}

// Bind socket to a port
int microtcp_bind(microtcp_sock_t *socket,
                  const struct sockaddr *address,
                  socklen_t address_len)
{
    CHECK_ERROR(socket, "Socket is not initialized");
    CHECK_ERROR(address, "Address is NULL");
    CHECK_ERROR(socket->state != INVALID, "Socket was not properly initialized" );

    CHECK_ERROR(bind(socket->sd, address, address_len) != MICROTCP_ERROR,
                "Bind Failed");

    socket->state = LISTEN;
    return 0;
}

// TODO(gtheo): Needs refactoring
int microtcp_connect(microtcp_sock_t *socket,
                     const struct sockaddr *address,
                     socklen_t address_len)
{

    CHECK_ERROR(socket, "Socket is not initialized");
    CHECK_ERROR(address, "Address is NULL");
    CHECK_ERROR(socket->state != INVALID,
                "Socket was not properly initialized");

    /* Header Creation Phase */
    microtcp_header_t rcv_header = {0};
    microtcp_header_t header =
        NEW_CONNECT_HEADER(socket->seq_number, socket->ack_number);
    header.checksum = crc32((uint8_t *)&header, sizeof(microtcp_header_t));

    LOG_INFO("Connect header checksum is %u", header.checksum);

    CHECK_ERROR(microtcp_header_hton(&header) != MICROTCP_ERROR);
    CHECK_ERROR(
        sendto(socket->sd, &header, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)address, address_len) != MICROTCP_ERROR,
        "Connect-> First send failed in connect!");

    CHECK_ERROR(recvfrom(socket->sd, &rcv_header, sizeof(microtcp_header_t),
                         MSG_WAITALL, (struct sockaddr *)address,
                         &address_len) != MICROTCP_ERROR,
                "Connect-> Receive timed out in connect!");

    CHECK_ERROR(microtcp_header_ntoh(&rcv_header));
    CHECK_ERROR(microtcp_header_ntoh(&header));

    uint32_t checksum = rcv_header.checksum;
    rcv_header.checksum = 0;
    rcv_header.checksum =
        crc32((uint8_t *)&rcv_header, sizeof(microtcp_header_t));

    LOG_INFO("Connect-> rcv_header.checksum == %u, checksum == %u",
             rcv_header.checksum, checksum);

    CHECK_ERROR(checksum == rcv_header.checksum &&
                rcv_header.control == SYN_ACK,
                "Connect-> Error during transmition");

    socket->ack_number    = rcv_header.seq_number + 1;
    socket->seq_number    = rcv_header.ack_number;
    socket->init_win_size = rcv_header.window;

    header.ack_number = socket->ack_number;
    header.seq_number = socket->seq_number;

    header.control = ACK_BIT;
    header.checksum = 0;
    header.checksum = crc32((uint8_t *)&header, sizeof(microtcp_header_t));

    LOG_INFO("Connect header checksum is %u", header.checksum);

    CHECK_ERROR(microtcp_header_hton(&header) != MICROTCP_ERROR);
    CHECK_ERROR(
        sendto(socket->sd, &header, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)address, address_len) != MICROTCP_ERROR,
        "Connect-> Second send failed in connect!");

    // Avoid having to store the dest socket address
    CHECK_ERROR(connect(socket->sd, address, address_len),
                "Connect call failed");

    // Establish the connection...
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    CHECK_ERROR(socket->recvbuf, "Connect-> rcv_buffer malloc failed!");

    socket->state = ESTABLISHED;

    return 0;
}

// TODO(gtheo): Needs refactoring
int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {

    CHECK_ERROR(socket, "Socket is not initialized");
    CHECK_ERROR(address, "Address is NULL");
    CHECK_ERROR(socket->state != INVALID, "Socket was not properly initialized");

    microtcp_header_t receive_header = {0};
    if (recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                 MSG_WAITALL, (struct sockaddr *)address,
                 &address_len) == MICROTCP_ERROR) {
        return MICROTCP_ERROR;
    }

    CHECK_ERROR(microtcp_header_ntoh(&receive_header));

    uint32_t checksum = receive_header.checksum;

    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    CHECK_ERROR(checksum == receive_header.checksum &&
                    receive_header.control == SYN_BIT,
                "Accept-> Error during transmition");

    socket->ack_number = receive_header.seq_number + 1;
    microtcp_header_t accept_header =
        NEW_ACCEPT_HEADER(socket->seq_number, socket->ack_number);

    accept_header.checksum =
        crc32((uint8_t *)&accept_header, sizeof(microtcp_header_t));

    microtcp_header_hton(&accept_header);
    CHECK_ERROR(sendto(socket->sd, &accept_header, sizeof(microtcp_header_t), 0,
                       address, address_len) == MICROTCP_ERROR);
    CHECK_ERROR(recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                         MSG_WAITALL, (struct sockaddr *)address,
                         &address_len) == MICROTCP_ERROR)

    microtcp_header_ntoh(&receive_header);

    checksum = receive_header.checksum;
    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    CHECK_ERROR(checksum == receive_header.checksum &&
                receive_header.control == ACK_BIT);

    socket->ack_number = receive_header.seq_number + 1;
    socket->seq_number = receive_header.ack_number;

    // Avoid having to store the dest socket address
    CHECK_ERROR(connect(socket->sd, address, address_len),
                "Connect call failed");

    // Establish the connection...
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    CHECK_ERROR(socket->recvbuf, "Connect-> rcv_buffer malloc failed!");

    socket->state = ESTABLISHED;

    return 0;
}

/**
 * Simulates the TCP POSIX shutdown()
 * Implements the connection termination process
 *
 * RESTRICTIONS:
 *      - Only the client can initiate the connection termination process
 *
 * NOTE: In this version @param how is not used
 *
 * TODO(gtheo): Needs refactoring
 */
int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    CHECK_ERROR(socket->state != INVALID,
                "Socket was not properly initialized");
    CHECK_ERROR(socket->state == ESTABLISHED,
                "The connection must be established to shut it down");

    /* Send FIN-ACK message to server */
    microtcp_header_t finalize_header =
        NEW_FINALIZE_HEADER(socket->seq_number, socket->ack_number);

    finalize_header.checksum =
        crc32((uint8_t *)&finalize_header, sizeof(microtcp_header_t));

    microtcp_header_hton(&finalize_header);

    CHECK_ERROR(send(socket->sd, &finalize_header, sizeof(microtcp_header_t),
                     0) != MICROTCP_ERROR,
                "Shutdown-> First send failed in connect!");

    /**
     * FOR PHASE II:
     *      Maybe add a middle State WAIT_ACK ???
     */

    /* Receive ACK message from server */
    microtcp_header_t receive_header = {0};
    CHECK_ERROR(recv(socket->sd, &receive_header, sizeof(microtcp_header_t),
                     MSG_WAITALL) == MICROTCP_ERROR);
    microtcp_header_ntoh(&receive_header);

    uint32_t checksum = receive_header.checksum;

    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    if (checksum != receive_header.checksum ||
        receive_header.control != ACK_BIT) {
        return MICROTCP_ERROR;
    }

    /* ACK = M + 1, Seq = N + 1 */
    socket->ack_number = receive_header.seq_number + 1;
    socket->seq_number = receive_header.ack_number;

    socket->state = CLOSING_BY_HOST;

    /* Receive FIN-ACK message from server */
    memset(&receive_header, 0, sizeof(microtcp_header_t));
    if (recv(socket->sd, &receive_header, sizeof(microtcp_header_t),
             MSG_WAITALL) == MICROTCP_ERROR) {
        return MICROTCP_ERROR;
    }
    microtcp_header_ntoh(&receive_header);

    checksum = receive_header.checksum;

    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    if (checksum != receive_header.checksum ||
        receive_header.control != FIN_ACK) {
        return MICROTCP_ERROR;
    }

    /* ACK: Y + 1, SEQ: N + 1 */
    socket->ack_number = receive_header.seq_number + 1;

    /* Send ACK message to server */
    finalize_header.control = ACK_BIT;
    finalize_header.ack_number = socket->ack_number;
    finalize_header.seq_number = socket->seq_number;

    finalize_header.checksum = 0;
    finalize_header.checksum =
        crc32((uint8_t *)&finalize_header, sizeof(microtcp_header_t));

    microtcp_header_hton(&finalize_header);
    if (send(socket->sd, &finalize_header, sizeof(microtcp_header_t), 0) ==
        MICROTCP_ERROR) {
        return MICROTCP_ERROR;
    }

    close(socket->sd);
    socket->state = CLOSED;

    return 0;
}


ssize_t microtcp_send(microtcp_sock_t *socket,
                      const void *buffer,
                      size_t length,
                      int flags)
{
    microtcp_header_t header  = {}; 
    size_t remaining      = 0,
           data_sent      = 0,
           chunks         = 0,
           bytes_send     = 0,
           bytes_to_send  = 0,
           cwnd           = socket->cwnd,
           ssthresh       = socket->ssthresh;

    uint8_t  dup_ack      = 0,
           * data         = malloc(MICROTCP_DATA_CHUNK_SIZE);

    assert(data && "Error: malloc failed");
    LOG_INFO("Microtcp_send flags == %d", flags);

    while (data_sent < length) 
    {
        bytes_to_send = MIN(remaining, socket->curr_win_size);
        bytes_to_send = MIN(bytes_to_send, cwnd);

        chunks        = bytes_to_send / MICROTCP_MSS;
        LOG_INFO("cwnd == %lu "
                 "remaining == %lu "
                 "curr_win_size == %lu", 
                 cwnd, remaining, socket->curr_win_size);

        LOG_INFO("No. chunks %lu, bytes to send %lu",
                 chunks, bytes_to_send );

        for (size_t i = 0 ; i < chunks ; i++) {

            LOG_INFO("Chunk no %lu\n" "Data to send from address inside buffer == %p",
                     i, buffer + (MICROTCP_DATA_CHUNK_SIZE * i));

            header = NEW_HEADER(socket->seq_number + (i * MICROTCP_MSS),
                                socket->ack_number,
                                MICROTCP_WIN_SIZE,
                                0,
                                MICROTCP_MSS,
                                0);

            LOG_INFO("Seq number %lu",
                     socket->seq_number + (i * MICROTCP_MSS));

            header.checksum = crc32(data, sizeof(header));
            header.checksum = update_crc32(header.checksum, 
                                           buffer + (MICROTCP_MSS * i),
                                           MICROTCP_MSS);

            LOG_INFO("The checksum is %u", header.checksum);

            memcpy(data,
                  (uint8_t*)&header,
                   sizeof(header));

            memcpy(data   + sizeof(header),
                   buffer + (MICROTCP_MSS * i),
                   MICROTCP_MSS);

            bytes_send = send(socket->sd,
                              data,
                              MICROTCP_DATA_CHUNK_SIZE, 
                              flags); 

            CHECK_ERROR(bytes_send != (ulong)MICROTCP_ERROR);

            socket->bytes_send += bytes_send;
            socket->packets_send++;
        }

        if (bytes_to_send % MICROTCP_MSS) {

            size_t data_sz  = (bytes_to_send % MICROTCP_MSS);
            size_t chunk_sz =  data_sz + sizeof(microtcp_header_t);

            memset(data, 0, MICROTCP_DATA_CHUNK_SIZE);
            
            header = NEW_HEADER(socket->seq_number + (chunks * MICROTCP_MSS),
                                socket->ack_number,
                                0,
                                MICROTCP_WIN_SIZE,
                                data_sz,
                                0);

            LOG_INFO("Seq number %lu",
                     socket->seq_number + (chunks * MICROTCP_MSS));

            header.checksum = crc32(data, sizeof(header));
            header.checksum = update_crc32(header.checksum, 
                                           buffer + (MICROTCP_MSS * chunks),
                                           data_sz);

            LOG_INFO("The checksum is %u", header.checksum);

            memcpy(data,
                  (uint8_t*)&header,
                   sizeof(header));

            memcpy(data   + sizeof(header),
                   buffer + (data_sz * chunks),
                   data_sz);

            bytes_send = send(socket->sd,
                              data,
                              chunk_sz,
                              flags);


            CHECK_ERROR(bytes_send != (ulong)MICROTCP_ERROR);

            socket->bytes_send += bytes_send;
            socket->packets_send++;

            chunks++;
            LOG_INFO("Chunk no %lu", chunks);
        }

        for (size_t i = 0; i < chunks ; i++) {

            ssize_t bytes_received = 0;
            bytes_received         = recv(socket->sd,
                                          data,
                                          MICROTCP_DATA_CHUNK_SIZE,
                                          0);

            if(bytes_received == MICROTCP_ERROR)
            {
                socket->bytes_lost += (bytes_to_send);
                socket->packets_lost++;
                break;
            }

            bytes_to_send -= ((i + 1) == chunks) ? 
                             (bytes_to_send % MICROTCP_MSS) :
                              MICROTCP_MSS;

            microtcp_header_t rcv_header;
            memcpy(&rcv_header, data, MICROTCP_HEADER_SZ);
            microtcp_header_ntoh(&rcv_header);

            socket->buf_fill_level  += bytes_received;

            socket->packets_received++;
            socket->bytes_received  += bytes_received;
        }

        free(data);
        remaining -= bytes_to_send;
        data_sent += bytes_to_send;
    }

    return 0;
}


ssize_t microtcp_recv(microtcp_sock_t *socket,
                      void *buffer,
                      size_t length,
                      int flags)
{
    microtcp_header_t send_header = {0};
    microtcp_header_t recv_header = {0};
    
    size_t   curr_buff_length  = 0;

    ssize_t   bytes_recvd = 0;
    ssize_t   bytes_sent  = 0;

    uint8_t*  data        = malloc(MICROTCP_DATA_CHUNK_SIZE);

    CHECK_ERROR(data, "Malloc Failed");

    // If the length is negative, return control to the user
    if (length <= 0)
    {
        free(data); 
        LOG_ERROR("Passed length is negative: %lu", length);
        return MICROTCP_ERROR;
    }

    //TODO(gtheo): Do a polling implementation
    while(curr_buff_length < length)
    {
        bytes_recvd = recv(socket->sd,
                           data,
                           MICROTCP_DATA_CHUNK_SIZE, 
                           flags);

        LOG_INFO("Receive-> We received %lu", bytes_recvd);

        // NOTE(gtheo): Do not know if it is the correct
        // way to handle this
        if (bytes_recvd == MICROTCP_ERROR) continue;

        memcpy(&recv_header, data, MICROTCP_HEADER_SZ);
        microtcp_header_ntoh(&recv_header);

        uint32_t checksum = recv_header.checksum;
        recv_header.checksum = 0;

        memcpy(data,&recv_header,MICROTCP_HEADER_SZ);
        recv_header.checksum = crc32(data, MICROTCP_DATA_CHUNK_SIZE);
        memcpy(data,&recv_header,MICROTCP_HEADER_SZ);


        if(recv_header.checksum == checksum)
        {
            LOG_ERROR("recv_header's checksum mismatch: %u == %u", 
                      recv_header.checksum, checksum);

            socket->packets_lost ++;
            socket->bytes_lost   +=  recv_header.data_len;
            // FIXME(gtheo): Will see if it works
            // This is not correct !!!
            continue;
        }

        // TODO(gtheo): Implement error handling logic
        //              Send ACK but
        if(socket->ack_number == recv_header.seq_number)
        {
            socket->ack_number += recv_header.data_len;

            memcpy(socket->recvbuf + socket->buf_fill_level, data + MICROTCP_HEADER_SZ , recv_header.data_len);
            socket->buf_fill_level += recv_header.data_len;
            socket->curr_win_size  = socket->init_win_size - socket->buf_fill_level;

            socket->packets_received ++;
            socket->bytes_received   += recv_header.data_len;
        }
        else
        {
            socket->packets_lost ++;
            socket->bytes_lost   += recv_header.data_len;
        }

        // TODO(gtheo): Send ACK
        send_header = NEW_HEADER(socket->seq_number,
                                 socket->ack_number,
                                 ACK_BIT,
                                 socket->curr_win_size,
                                 0,
                                 0);
        
        bytes_sent = send(socket->sd,
                          &send_header,
                          MICROTCP_HEADER_SZ,
                          0);

        CHECK_ERROR(bytes_sent != MICROTCP_ERROR,
                    "Send Failed");

        // Increament seq number
        socket->seq_number++;

        size_t to_copy = (socket->buf_fill_level < length - curr_buff_length) ?
                          socket->buf_fill_level : length - curr_buff_length;

        memcpy(buffer + curr_buff_length, socket->recvbuf ,to_copy);

        curr_buff_length += to_copy;
        socket->buf_fill_level -= to_copy;

        memmove(socket->recvbuf, socket->recvbuf + to_copy, socket->buf_fill_level);
    }
    
    free(data);
    return curr_buff_length;
}


ssize_t
microtcp_recv_fsm(microtcp_sock_t *socket,
                  void *buffer,
                  size_t length,
                  int flags)
{
    return 0;
}
