#include "microtcp_utils.h"

#include <netinet/in.h>
#include <stdlib.h>

microtcp_header_t microtcp_header_new(
    uint32_t seq_number,  /**< Sequence number */
    uint32_t ack_number,  /**< ACK number */
    uint16_t control,     /**< Control bits (e.g. SYN, ACK, FIN) */
    uint16_t window,      /**< Window size in bytes */
    uint32_t data_len,    /**< Data length in bytes (EXCLUDING header) */
    uint32_t future_use0, /**< 32-bits for future use */
    uint32_t future_use1, /**< 32-bits for future use */
    uint32_t future_use2, /**< 32-bits for future use */
    uint32_t checksum     /**< CRC-32 checksum, see crc32() in utils folder */
) {
    microtcp_header_t new_header = {seq_number,  ack_number,  control,
                                    window,      data_len,    future_use0,
                                    future_use1, future_use2, checksum};

    return (new_header);
}

int32_t microtcp_header_ntoh(microtcp_header_t *header) {

    if (header == NULL) return MICROTCP_ERROR;

    header->seq_number  = ntohl(header->seq_number);
    header->ack_number  = ntohl(header->ack_number);
    header->control     = ntohs(header->control);
    header->window      = ntohs(header->window);
    header->data_len    = ntohl(header->data_len);
    header->future_use0 = ntohl(header->future_use0);
    header->future_use1 = ntohl(header->future_use1);
    header->future_use2 = ntohl(header->future_use2);
    header->checksum    = ntohl(header->checksum);

    return 0;
}

int32_t microtcp_header_hton(microtcp_header_t *header) {

    if (header == NULL) return MICROTCP_ERROR;

    header->seq_number  = htonl(header->seq_number);
    header->ack_number  = htonl(header->ack_number);
    header->control     = htons(header->control);
    header->window      = htons(header->window);
    header->data_len    = htonl(header->data_len);
    header->future_use0 = htonl(header->future_use0);
    header->future_use1 = htonl(header->future_use1);
    header->future_use2 = htonl(header->future_use2);
    header->checksum    = htonl(header->checksum);

    return 0;
}
