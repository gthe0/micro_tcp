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

microtcp_header_t microtcp_header_ntoh(microtcp_header_t *header) {
    microtcp_header_t ntoh_header = {0};
    if (header == NULL) return;

    ntoh_header.seq_number = ntohl(header->seq_number);
    ntoh_header.ack_number = ntohl(header->ack_number);
    ntoh_header.control = ntohs(header->control);
    ntoh_header.window = ntohs(header->window);
    ntoh_header.data_len = ntohl(header->data_len);
    ntoh_header.future_use0 = ntohl(header->future_use0);
    ntoh_header.future_use1 = ntohl(header->future_use1);
    ntoh_header.future_use2 = ntohl(header->future_use2);
    ntoh_header.checksum = ntohl(header->checksum);

    return ntoh_header;
}

microtcp_header_t microtcp_header_hton(microtcp_header_t *header) {
    microtcp_header_t hton_header = {0};
    if (header == NULL) return;

    hton_header.seq_number = htonl(header->seq_number);
    hton_header.ack_number = htonl(header->ack_number);
    hton_header.control = htons(header->control);
    hton_header.window = htons(header->window);
    hton_header.data_len = htonl(header->data_len);
    hton_header.future_use0 = htonl(header->future_use0);
    hton_header.future_use1 = htonl(header->future_use1);
    hton_header.future_use2 = htonl(header->future_use2);
    hton_header.checksum = htonl(header->checksum);

    return hton_header;
}
