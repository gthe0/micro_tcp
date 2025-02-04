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

static ssize_t buffer_copy(microtcp_sock_t *socket,
                           void *buffer,
                           size_t length,
                           ssize_t curr_buff_length);

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

    if((socket_obj.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) == MICROTCP_ERROR)
    {
        LOG_ERROR("Socket could not be opened.");
        socket_obj.state = INVALID;
    }

    if(setsockopt(socket_obj.sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        LOG_ERROR("Setting SO_REUSEADDR failed.");
        socket_obj.state = INVALID;
    }

    return (socket_obj);
}

// Bind socket to a port
int microtcp_bind(microtcp_sock_t *socket,
                  const struct sockaddr *address,
                  socklen_t address_len)
{
    if(address == NULL)
    {
        LOG_ERROR("Address is NULL");
        return MICROTCP_ERROR;
    }

    if(socket == NULL)
    {
        LOG_ERROR("Socket is not initialized");
        return MICROTCP_ERROR;
    }

    if(socket->state == INVALID)
    {
        LOG_ERROR("Socket is in an invalid state!");
        return MICROTCP_ERROR;
    }

    if(bind(socket->sd, address, address_len) == MICROTCP_ERROR)
    {
        LOG_ERROR("");
        perror("Bind Failed");
        return MICROTCP_ERROR;
    }

    socket->state = LISTEN;
    return 0;
}

// TODO(gtheo): Needs refactoring
int microtcp_connect(microtcp_sock_t *socket,
                     const struct sockaddr *address,
                     socklen_t address_len)
{
    if(address == NULL)
    {
        LOG_ERROR("Address is NULL");
        return MICROTCP_ERROR;
    }

    if(socket == NULL)
    {
        LOG_ERROR("Socket is not initialized");
        return MICROTCP_ERROR;
    }

    if(socket->state == INVALID)
    {
        LOG_ERROR("Socket is in an invalid state!");
        return MICROTCP_ERROR;
    }

    // Time out interval
    struct timeval timeout = {
        .tv_sec = 10,
        .tv_usec = 0
    };

    CHECK_ERROR((setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO,
                            &timeout, sizeof(struct timeval)) >= 0),
                "Time Interval option failed");

    /* Header Creation Phase */
    microtcp_header_t rcv_header = {0};
    microtcp_header_t header = NEW_CONNECT_HEADER(socket->seq_number, 
                                                  socket->ack_number);

    header.checksum = crc32((uint8_t *)&header, sizeof(microtcp_header_t));

    LOG_INFO("Connect header checksum is %x", header.checksum);
    CHECK_ERROR(microtcp_header_hton(&header) != MICROTCP_ERROR);

    // First Send of the 3-way handshake
    if(sendto(socket->sd, &header, sizeof(microtcp_header_t), 0,
             (struct sockaddr *)address, address_len) < 0)
    {
        LOG_ERROR("Connect-> First send failed!");
        return MICROTCP_ERROR;
    }

    socket->packets_send++;

    if(recvfrom(socket->sd, &rcv_header, sizeof(microtcp_header_t), 
                0, (struct sockaddr *)address, &address_len) < 0)
    {
        LOG_ERROR("Connect-> receive failed!");
        return MICROTCP_ERROR;
    }

    socket->packets_received++;

    CHECK_ERROR(microtcp_header_ntoh(&rcv_header) != MICROTCP_ERROR);
    CHECK_ERROR(microtcp_header_ntoh(&header)     != MICROTCP_ERROR);

    uint32_t checksum = rcv_header.checksum;
    rcv_header.checksum = 0;
    rcv_header.checksum =
        crc32((uint8_t *)&rcv_header, sizeof(microtcp_header_t));

    LOG_INFO("Connect-> rcv_header.checksum == %x, checksum == %x",
             rcv_header.checksum, checksum);

    // Check if the checksum is correct
    if(checksum != rcv_header.checksum)
    {
        LOG_ERROR("Checksum mismatch %x and %x", checksum, rcv_header.checksum);
        return MICROTCP_ERROR;
    }
     
    // Check whether we got a SYN_ACK or not
    if(rcv_header.control != SYN_ACK)
    {
        LOG_ERROR("The Received packet was not a SYN_ACK: %x", rcv_header.control);
        return MICROTCP_ERROR;
    }

    // Check ACK and Sequence Numbers
    if(rcv_header.ack_number != socket->seq_number + 1)
    {
        LOG_ERROR("Socket seq number and packet ack number mismatch!");
        return MICROTCP_ERROR;
    }

    socket->ack_number    = rcv_header.seq_number + 1;
    socket->seq_number    = rcv_header.ack_number;
    socket->init_win_size = rcv_header.window;

    LOG_INFO("Connect header seq_number is %lu", socket->ack_number);
    LOG_INFO("Connect header ack_number is %lu", socket->seq_number);

    header.ack_number = socket->ack_number;
    header.seq_number = socket->seq_number;

    header.control = ACK_BIT;
    header.checksum = 0;
    header.checksum = crc32((uint8_t *)&header, sizeof(microtcp_header_t));

    LOG_INFO("Connect header checksum is %x", header.checksum);
    CHECK_ERROR(microtcp_header_hton(&header) != MICROTCP_ERROR);

    // First Send of the 3-way handshake
    if(sendto(socket->sd, &header, sizeof(microtcp_header_t), 0,
             (struct sockaddr *)address, address_len) < 0)
    {
        LOG_ERROR("Connect-> First send failed!");
        return MICROTCP_ERROR;
    }

    socket->packets_send++;
    // Avoid having to store the dest socket address
    if(connect(socket->sd, address, address_len) == MICROTCP_ERROR)
    {
        LOG_ERROR("Connect call failed");
        return MICROTCP_ERROR;
    }

    // Set the timeout timer for the sender
    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

    CHECK_ERROR((setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO,
                            &timeout, sizeof(struct timeval)) >= 0),
                "Time Interval option failed");

    // Establish the connection...
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    CHECK_ERROR(socket->recvbuf, "Connect-> rcv_buffer malloc failed!");

    socket->init_win_size = MICROTCP_RECVBUF_LEN;
    socket->curr_win_size = MICROTCP_RECVBUF_LEN;

    socket->state = ESTABLISHED;

    return 0;
}

// TODO(gtheo): Needs refactoring
int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {

    CHECK_ERROR(socket, "Socket is not initialized");
    CHECK_ERROR(address, "Address is NULL");
    CHECK_ERROR(socket->state == LISTEN,
                "Bind was not called by the server");

    // Time out interval
    struct timeval timeout = {
        .tv_sec = 300,
        .tv_usec = 0
    };

    CHECK_ERROR((setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO,
                            &timeout, sizeof(struct timeval)) >= 0),
                "Time Interval option failed");

    microtcp_header_t receive_header = {0};
    CHECK_ERROR(recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                 0, (struct sockaddr *)address, &address_len) != MICROTCP_ERROR);

    CHECK_ERROR(microtcp_header_ntoh(&receive_header) != MICROTCP_ERROR);

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
                       address, address_len) != MICROTCP_ERROR);

    CHECK_ERROR(recvfrom(socket->sd, &receive_header, sizeof(microtcp_header_t),
                         0, (struct sockaddr *)address,
                         &address_len) != MICROTCP_ERROR)

    microtcp_header_ntoh(&receive_header);

    checksum = receive_header.checksum;
    receive_header.checksum = 0;
    receive_header.checksum =
        crc32((uint8_t *)&receive_header, sizeof(microtcp_header_t));

    CHECK_ERROR(checksum == receive_header.checksum &&
                receive_header.control == ACK_BIT);

    socket->ack_number = receive_header.seq_number;
    socket->seq_number = receive_header.ack_number;

    LOG_INFO("Accept header seq_number is %lu", socket->ack_number);
    LOG_INFO("Accept header ack_number is %lu", socket->seq_number);

    // Avoid having to store the dest socket address
    if(connect(socket->sd, address, address_len) == MICROTCP_ERROR)
    {
        LOG_ERROR("Connect call failed");
        return MICROTCP_ERROR;
    }

    // Establish the connection...
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    CHECK_ERROR(socket->recvbuf, "Connect-> rcv_buffer malloc failed!");

    socket->init_win_size = MICROTCP_RECVBUF_LEN;
    socket->curr_win_size = MICROTCP_RECVBUF_LEN;

    socket->state = ESTABLISHED;

    timeout.tv_usec = 0;
    CHECK_ERROR((setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO,
                            &timeout, sizeof(struct timeval)) >= 0),
                "Time Interval option failed");

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
    CHECK_ERROR(socket->state == CLOSING_BY_PEER,
                "Socket was not properly initialized");
    CHECK_ERROR(socket->state == ESTABLISHED,
                "The connection must be established to shut it down");

    LOG_INFO("socket->seq_number & ack_number: %lu, %lu", socket->seq_number, socket->ack_number);

    // Time out interval
    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = MICROTCP_ACK_TIMEOUT_US
    };

    CHECK_ERROR((setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO,
                            &timeout, sizeof(struct timeval)) >= 0),
                "Time Interval option failed");

    if(socket->state == ESTABLISHED)
    {
        /* Send FIN-ACK message to server */
        microtcp_header_t finalize_header =
            NEW_FINALIZE_HEADER(socket->seq_number, socket->ack_number);

        finalize_header.checksum =
            crc32((uint8_t *)&finalize_header, sizeof(microtcp_header_t));

        microtcp_header_hton(&finalize_header);

        CHECK_ERROR(send(socket->sd, &finalize_header, sizeof(microtcp_header_t),
                         0) != MICROTCP_ERROR,
                    "Shutdown-> First send failed in connect!");

        microtcp_header_ntoh(&finalize_header);

        /* Receive ACK message from server */
        microtcp_header_t receive_header = {0};
        CHECK_ERROR(recv(socket->sd, &receive_header, sizeof(microtcp_header_t),
                         MSG_WAITALL) != MICROTCP_ERROR);
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
                 MSG_WAITALL) != MICROTCP_ERROR) {
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
        if (send(socket->sd, &finalize_header, sizeof(microtcp_header_t), 0) != MICROTCP_ERROR) {
            return MICROTCP_ERROR;
        }

        socket->state = CLOSED;
    }
    else if(socket->state == CLOSING_BY_PEER)
    {
        microtcp_header_t ack_header = NEW_FINALIZE_HEADER(socket->seq_number, socket->ack_number);
        ack_header.control = ACK_BIT;

        ack_header.checksum =
            crc32((uint8_t *)&ack_header, sizeof(microtcp_header_t));

        microtcp_header_hton(&ack_header);

        CHECK_ERROR(send(socket->sd, &ack_header, sizeof(microtcp_header_t),
                         0) != MICROTCP_ERROR,
                    "Shutdown-> First send failed in connect!");

        socket->seq_number++;

        /* Send FIN-ACK message to server */
        microtcp_header_t finalize_header =
            NEW_FINALIZE_HEADER(socket->seq_number, socket->ack_number);

        finalize_header.checksum =
            crc32((uint8_t *)&finalize_header, sizeof(microtcp_header_t));

        microtcp_header_hton(&finalize_header);

        CHECK_ERROR(send(socket->sd, &finalize_header, sizeof(microtcp_header_t),
                         0) != MICROTCP_ERROR,
                    "Shutdown-> First send failed in connect!");

        /* Receive ACK message from server */
        microtcp_header_t receive_header = {0};
        CHECK_ERROR(recv(socket->sd, &receive_header, sizeof(microtcp_header_t),
                         MSG_WAITALL) != MICROTCP_ERROR);
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

        socket->state = CLOSED;
    }

    return 0;
}


ssize_t microtcp_send(microtcp_sock_t *socket,
                      const void *buffer,
                      size_t length,
                      int flags)
{
    microtcp_header_t recv_header  = {}; 
    microtcp_header_t header  = {}; 

    size_t 
    remaining      = length,
    data_sent      = 0,
    chunks         = 0,
    bytes_send     = 0,
    bytes_to_send  = 0;

    uint8_t dup_ack       = 0,
    data[MICROTCP_DATA_CHUNK_SIZE] = {0};

    LOG_INFO("Microtcp_send flags == %d", flags);

    // NOTE(gtheo): If the length is negative, return control to the user
    if (length <= 0    || buffer == NULL               ||
        socket == NULL || socket->state != ESTABLISHED )
    {
        LOG_ERROR("microtcp_recv Illegal parameters");
        errno = EINVAL;

        return MICROTCP_ERROR;
    }

    // NOTE(gtheo): Loop until all data is sent
    while (data_sent < length) 
    {
        memset(data,0,MICROTCP_DATA_CHUNK_SIZE);
        bytes_to_send = MIN(remaining, socket->curr_win_size);
        bytes_to_send = MIN(bytes_to_send, socket->cwnd);

        chunks        = bytes_to_send / MICROTCP_MSS;

        LOG_INFO("cwnd == %lu "
                 "remaining == %lu "
                 "curr_win_size == %lu", 
                 socket->cwnd, remaining, socket->curr_win_size);

        LOG_INFO("No. chunks %lu, bytes to send %lu",
                 chunks, bytes_to_send );

        // NOTE(gtheo): Dead code it seems
        for (size_t i = 0 ; i < chunks ; i++) {
            LOG_INFO("Chunk no %lu\n" "Data to send from address inside buffer == %p",
                     i, buffer + (MICROTCP_DATA_CHUNK_SIZE * i));

            header = NEW_HEADER(socket->seq_number + (i * MICROTCP_MSS),
                                socket->ack_number,
                                socket->curr_win_size,
                                0,
                                MICROTCP_MSS,
                                0);

            LOG_INFO("Seq number %lu",
                     socket->seq_number + (i * MICROTCP_MSS));

            header.checksum = crc32(data, sizeof(header));
            header.checksum = update_crc32(header.checksum, 
                                           buffer + (MICROTCP_MSS * i),
                                           MICROTCP_MSS);

            LOG_INFO("The checksum is %x", header.checksum);

            microtcp_header_hton(&header);

            memset(data,0,MICROTCP_DATA_CHUNK_SIZE);
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

            if(bytes_send == (ulong)MICROTCP_ERROR)
            {
                LOG_ERROR("send failed");
                socket->bytes_lost += MICROTCP_DATA_CHUNK_SIZE;
                socket->packets_lost++;

                return MICROTCP_ERROR;
            }

            socket->bytes_send += MICROTCP_DATA_CHUNK_SIZE;
            socket->packets_send++;
        }

        if (bytes_to_send % MICROTCP_MSS) {

            size_t data_sz  = (bytes_to_send % MICROTCP_MSS);
            size_t chunk_sz =  data_sz + sizeof(microtcp_header_t);

            memset(data, 0, MICROTCP_DATA_CHUNK_SIZE);
            
            // Initialize header to send
            header = (microtcp_header_t) {
               .seq_number = socket->seq_number + (chunks * MICROTCP_MSS),
               .ack_number = socket->ack_number,
               .window     = socket->curr_win_size,
               .data_len   = data_sz
            };
            
            LOG_INFO("Seq number %lu",
                     socket->seq_number + (chunks * MICROTCP_MSS));

            header.checksum = crc32(data, sizeof(header));
            header.checksum = update_crc32(header.checksum, 
                                           buffer + (MICROTCP_MSS * chunks),
                                           data_sz);

            LOG_INFO("The checksum is %x", header.checksum);

            microtcp_header_hton(&header);

            memcpy(data,
                  (uint8_t*)&header,
                   sizeof(header));

            memcpy(data   + sizeof(header),
                   buffer + (MICROTCP_MSS * chunks),
                   data_sz);

            bytes_send = send(socket->sd,
                              data,
                              chunk_sz,
                              flags);


            if(bytes_send == (ulong)MICROTCP_ERROR)
            {
                LOG_ERROR("send failed");
                socket->bytes_lost += chunk_sz;
                socket->packets_lost++;

                return MICROTCP_ERROR;
            }

            socket->bytes_send += chunk_sz;
            socket->packets_send++;

            chunks++;
            LOG_INFO("Chunk no %lu", chunks);
        }

        if(bytes_to_send == 0       ||
           socket->curr_win_size == 0)
        {
            LOG_INFO("Curr_win_size  %lu == %lu and chunks == %lu",
                     bytes_to_send, socket->curr_win_size, chunks);
            LOG_WARN("FLOW CONTROL -> curr_win_size == 0");

            header = NEW_HEADER(socket->seq_number,
                                socket->ack_number,
                                socket->curr_win_size,
                                0, 0, 0);

            header.checksum = crc32((uint8_t*)&header,
                                     MICROTCP_HEADER_SZ);

            microtcp_header_hton(&header);
            send(socket->sd,
                 &header,
                 MICROTCP_HEADER_SZ,
                 flags);

            chunks++;
            usleep(rand()%MICROTCP_ACK_TIMEOUT_US);
        }

        bytes_to_send = 0;
        for (size_t i = 0; i < chunks ; i++) {

            memset(data,0,MICROTCP_DATA_CHUNK_SIZE);
            // TODO(gtheo): Implement packet reception logic
            ssize_t recv_bytes = recv(socket->sd, 
                                      data,
                                      MICROTCP_HEADER_SZ,
                                      0);

            LOG_INFO("Receive-> We received %ld", recv_bytes);

            // If we encountered any errors related to 
            // the timeout, then break
            if (recv_bytes == MICROTCP_ERROR) 
            {
                if(errno == EAGAIN || errno == ETIMEDOUT)
                {
                    // Entering slow start...
                    socket->ssthresh = socket->cwnd/2;
                    socket->cwnd = MIN( MICROTCP_MSS , socket->ssthresh);

                    break;
                }
                else return MICROTCP_ERROR;
            }

            memcpy(&recv_header, data, MICROTCP_HEADER_SZ);
            microtcp_header_ntoh(&recv_header);

            uint32_t checksum = recv_header.checksum;

            recv_header.checksum = 0;
            recv_header.checksum = crc32(data, MICROTCP_HEADER_SZ);

            if(recv_header.checksum != checksum)
            {
                LOG_ERROR("recv_header's checksum mismatch: %x == %x", 
                          recv_header.checksum, checksum);

                socket->packets_lost ++;
                socket->bytes_lost   +=  recv_header.data_len;

                break;            
            }

            if(recv_header.control & ACK_BIT)
            {
                if(socket->seq_number > recv_header.ack_number)
                {
                    bytes_to_send        += recv_header.ack_number - socket->seq_number;
                    socket->seq_number    = recv_header.ack_number;
                    socket->curr_win_size = recv_header.window;

                    dup_ack = 0;

                    if(socket->cwnd < socket->ssthresh)
                    {
                        socket->cwnd *= 2;
                        LOG_INFO("SLOW START socket->cwnd = %lu", socket->cwnd);
                    }
                    else
                    {
                        socket->cwnd += MICROTCP_MSS;
                        LOG_INFO("SLOW START socket->cwnd = %lu", socket->cwnd);
                    }
                    
                }
                else if(++dup_ack == 3)
                {
                    dup_ack = 0;

                    // Entering fast recovery...
                    socket->ssthresh = socket->cwnd/2;
                    socket->cwnd     = socket->cwnd/2 + 1;

                    break;
                }
            }
        }
        remaining -= bytes_to_send;
        data_sent += bytes_to_send;
    }

    return (data_sent);
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

    uint8_t   data[MICROTCP_DATA_CHUNK_SIZE] = {0};

    // If the length is negative, return control to the user
    if (length <= 0 || buffer == NULL || socket == NULL ||
        socket->state == CLOSED || socket->state == CLOSING_BY_PEER ||
        socket->state == INVALID )
    {
        LOG_ERROR("microtcp_recv Illegal parameters");
        errno = EINVAL;

        return MICROTCP_ERROR;
    }

    // Log the information for debugging purposes
    LOG_INFO("buffer length == %lu\n"
             "socket->buf_fill_level == %lu"
             "flags == %u \n",
             length, 
             socket->buf_fill_level,
             flags);

    // NOTE(gtheo): Let's avoid getting in the loop
    if(socket->buf_fill_level > 0)
    {
        curr_buff_length += buffer_copy(socket,
                                        buffer,
                                        length,
                                        curr_buff_length);
    }

    //TODO(gtheo): Do a polling implementation
    while(curr_buff_length < length)
    {
        memset(data,0,MICROTCP_DATA_CHUNK_SIZE);
        bytes_recvd = recv(socket->sd,
                           data,
                           MICROTCP_DATA_CHUNK_SIZE, 
                           flags);

        LOG_INFO("Receive-> We received %lu", bytes_recvd);

        // NOTE(gtheo): Receiver always blocks, that means that
        // something went wrong with the reception of the packet.
        if (bytes_recvd == MICROTCP_ERROR) return MICROTCP_ERROR;

        memcpy(&recv_header, data, MICROTCP_HEADER_SZ);
        microtcp_header_ntoh(&recv_header);

        uint32_t checksum = recv_header.checksum;

        LOG_INFO("BEFORE: checksum is: %x", recv_header.checksum);

        recv_header.checksum = 0;
        recv_header.checksum = crc32((uint8_t*)&recv_header, MICROTCP_HEADER_SZ);

        recv_header.checksum = update_crc32(recv_header.checksum,
                                            data + MICROTCP_HEADER_SZ,
                                            recv_header.data_len);

        LOG_INFO("AFTER: checksum is: %x", recv_header.checksum);

        if(recv_header.checksum != checksum)
        {
            LOG_ERROR("recv_header's checksum mismatch: %x == %x", 
                      recv_header.checksum, checksum);

            socket->packets_lost ++;
            socket->bytes_lost   +=  recv_header.data_len;

            // NOTE(gtheo): Not sure
            continue;
        }

        // TODO(gtheo): Implement error handling logic
        //              Send ACK back
        if(socket->ack_number == recv_header.seq_number &&
           socket->curr_win_size > 0)
        {
            LOG_INFO("IF ack_number == seq_number");
            socket->ack_number += recv_header.data_len;

            memcpy(socket->recvbuf + socket->buf_fill_level, data + MICROTCP_HEADER_SZ , recv_header.data_len);
            socket->buf_fill_level += recv_header.data_len;
            socket->curr_win_size  = socket->init_win_size - socket->buf_fill_level;

            socket->packets_received ++;
            socket->bytes_received   += recv_header.data_len;
        }
        else
        {
            LOG_INFO("\nELSE %lu == %u, curr_win_size = %lu !",
                     socket->ack_number, recv_header.seq_number,
                     socket->curr_win_size);

            socket->packets_lost ++;
            socket->bytes_lost   += recv_header.data_len;
        }

        // Closing by Peer
        if(recv_header.control & FIN_ACK)
        {
            socket->state = CLOSING_BY_PEER;
            // FIXME(gtheo): Add a shutdown call or make different error codes
            return MICROTCP_ERROR;
        }

        // TODO(gtheo): Send ACK
        send_header = NEW_HEADER(socket->seq_number,
                                 socket->ack_number,
                                 ACK_BIT,
                                 socket->curr_win_size,
                                 0,
                                 0);

        send_header.checksum = crc32((uint8_t*)&send_header, 
                                     MICROTCP_HEADER_SZ);

        microtcp_header_hton(&send_header);

        bytes_sent = send(socket->sd,
                          &send_header,
                          MICROTCP_HEADER_SZ,
                          0);

        // NOTE(gtheo): Looks ugly
        if(bytes_sent == MICROTCP_ERROR)
        {
            LOG_ERROR("send operation failed!");
            return MICROTCP_ERROR;
        }

        // Increament sequence number
        socket->seq_number   ++;
        socket->packets_send ++;
        socket->bytes_received += MICROTCP_HEADER_SZ;

        curr_buff_length += buffer_copy(socket,
                                        buffer,
                                        length,
                                        curr_buff_length);
    }
    
    return (curr_buff_length);
}


// NOTE(gtheo): Return the number of bytes that where copied
static ssize_t buffer_copy(microtcp_sock_t *socket,
                           void *buffer,
                           size_t length,
                           ssize_t curr_buff_length)
{
    size_t to_copy = (socket->buf_fill_level < length - curr_buff_length) ?
                      socket->buf_fill_level : length - curr_buff_length;

    socket->buf_fill_level -= to_copy;
    socket->curr_win_size   = socket->init_win_size - socket->buf_fill_level;

    memcpy((uint8_t*)buffer + curr_buff_length, socket->recvbuf ,to_copy);
    memmove(socket->recvbuf, socket->recvbuf + to_copy, socket->buf_fill_level);

    return to_copy;
}
