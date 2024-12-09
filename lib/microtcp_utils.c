#include "microtcp_utils.h"

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
)
{
    microtcp_header_t new_header = {
        seq_number,
        ack_number,
        control,
        window,
        data_len,
        future_use0,
        future_use1,
        future_use2,
        checksum
    };

    return (new_header);
}

