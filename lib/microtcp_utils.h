#include "microtcp.h"

#include <log.h>

#define ACK_BIT     (1<<12)
#define RST_BIT     (1<<13)
#define SYN_BIT     (1<<14)
#define FIN_BIT     (1<<15)

#define FIN_ACK     ((FIN_BIT) | (ACK_BIT))
#define SYN_ACK     ((SYN_BIT) | (ACK_BIT))

#define MICROTCP_ERROR -1
#define NEW_HEADER(seq_number, ack_number, control, win_sz, data_len, checksum)     \
    microtcp_header_new(seq_number, ack_number, control, win_sz, \
                        data_len, 0, 0, 0, checksum)

#define NEW_CONNECT_HEADER(seq_number,ack_number)\
    NEW_HEADER(seq_number, ack_number, (SYN_BIT),\
               MICROTCP_WIN_SIZE, 0, 0)

#define NEW_ACCEPT_HEADER(seq_number,ack_number)\
    NEW_HEADER(seq_number, ack_number, (SYN_ACK),\
               MICROTCP_WIN_SIZE, 0, 0)

#define NEW_FINALIZE_HEADER(seq_number,ack_number)\
    NEW_HEADER(seq_number, ack_number, (FIN_ACK),\
               MICROTCP_WIN_SIZE,0, 0)

microtcp_header_t microtcp_header_new(
  uint32_t seq_number,          /**< Sequence number */
  uint32_t ack_number,          /**< ACK number */
  uint16_t control,             /**< Control bits (e.g. SYN, ACK, FIN) */
  uint16_t window,              /**< Window size in bytes */
  uint32_t data_len,            /**< Data length in bytes (EXCLUDING header) */
  uint32_t future_use0,         /**< 32-bits for future use */
  uint32_t future_use1,         /**< 32-bits for future use */
  uint32_t future_use2,         /**< 32-bits for future use */
  uint32_t checksum             /**< CRC-32 checksum, see crc32() in utils folder */
);

microtcp_header_t microtcp_header_ntoh(microtcp_header_t *header);
microtcp_header_t microtcp_header_hton(microtcp_header_t *header);

