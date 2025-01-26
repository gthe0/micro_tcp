#include "microtcp.h"

#include <log.h>
#include <stdlib.h>

#define ACK_BIT     1<<12
#define RST_BIT     1<<13
#define SYN_BIT     1<<14
#define FIN_BIT     1<<15

#define ACCEPT_CTRL   (SYN_BIT | ACK_BIT)
#define CONNECT_CTRL  (SYN_BIT)
#define FINALIZE_CTRL (FIN_BIT | ACK_BIT)

#define NEW_CONNECT_HEADER(seq_number,ack_number)\
    microtcp_header_new(seq_number,ack_number,(CONNECT_CTRL),\
                        MICROTCP_WIN_SIZE ,0,0,0,0,0)


#define NEW_ACCEPT_HEADER(seq_number,ack_number)\
    microtcp_header_new(seq_number,ack_number,(ACCEPT_CTRL),\
                        MICROTCP_WIN_SIZE ,0,0,0,0,0)


#define NEW_FINALIZE_HEADER(seq_number,ack_number)\
    microtcp_header_new(seq_number,ack_number,(FINALIZE_CTRL),\
                        MICROTCP_WIN_SIZE ,0,0,0,0,0)


// Error return
#define CHECK_ERROR(check, message, ...)\
    if(check){}else{LOG_ERROR(message, ##__VA_ARGS__); return EXIT_FAILURE;}

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

