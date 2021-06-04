/** @file ham_messaging_sys_task.h
 *  @brief HAM Radio Messaging System Task Header.
 */

#ifndef HAM_MESSAGING_SYS_TASK_H
#define HAM_MESSAGING_SYS_TASK_H

#include "app/rob3u/ttc_setup.h"

#define HAM_SEND_MSG_CMD 's'              /**< Byte to identify the send message command. */
#define HAM_ASK_MSG_CMD 'a'               /**< Byte to identify the ask message command. */
#define HAM_GET_CACHE_CMD 'c'             /**< Byte to identify the get cache data command. */
#define HAM_MAX_MSG_NUM 20                /**< Maximum number of storable messages. */
#define HAM_MAX_MSG_LEN 20                /**< The maximum length of the message. */
#define HAM_ALLOWED_MSG_NUM 1             /**< The maximum allowed number of storable message per person. */
#define HAM_MAX_ID_LEN 20                 /**< The maximum length of the ham packet data without the message. */
#define HAM_SENT_MSG_DELAY 10             /**< The time given before deleting messages with the sent tag in second. */
#define HAM_NOT_SENT_MSG_DELAY 60         /**< The time given before deleting messages with the not sent tag in second. */
#define HAM_CALL_SIGN_LEN 6               /**< The length of the the call sign. */
#define HAM_MSG_ERASABLE_TAG 0x00         /**< Tag of the packet indicating that it can be replaced by another packet. */
#define HAM_MSG_NOT_SENT_TAG 0x01         /**< Tag of the packet indicating that it was not sent. */
#define HAM_MSG_SENT_TAG 0x02             /**< Tag of the packet indicating that it was sent. */
#define HAM_MSG_STORED 0x03               /**< ACK message code saying that the message is stored. */
#define HAM_INV_CMD 0x04                  /**< NACK message code that saying that the command is invalid. */
#define HAM_MAX_MSG_NUM_REACHED 0x05      /**< NACK message code that saying that the storable maximum message number has been reached. */
#define HAM_INV_PKT 0x06                  /**< NACK message code that saying that the packet is invalid. */
#define HAM_NO_MSG 0x07                   /**< NACK message code that saying that there is no message for the given call sign. */
#define HAM_MAX_MSG_LEN_EXCEED 0x08       /**< NACK message code that saying that the the maximum length of the message exceeded. */
#define HAM_ALLOWED_MSG_NUM_REACHED 0x09  /**< NACK message code that saying that the maximum allowed number of storable message per person has been reached. */
#define HAM_NO_CHACHE_DATA 0x0A           /**< NACK message code that saying that there is no chache data. */
#define HAM_ACK_NACK_PKT_LEN 2            /**< The data lengt of the ACK/NACK packet. */
#define HAM_MSG_EEPROM_ADDR 0             /**< Eeprom starting addres of the saved packet. */
#define HAM_TAG_LEN 1                     /**< Packet tag length. */
#define HAM_CRC_LEN 2                     /**< HAM_CRC_length. */
#define HAM_TIMESTAMP_LEN 4               /**< Packet timestamp length. */
#define HAM_CACHE_MSG_DATA_LEN (uint8_t)((HAM_CALL_SIGN_LEN*2)+(HAM_TAG_LEN)+(HAM_TIMESTAMP_LEN)) /**< The total length of the data saved in the cache for one ham packet. */
#define HAM_MAX_CACHE_MSG_NUM (uint8_t)(((TTC_CSP_BUFFER_DATA_SIZE)-(TTC_CSP_CRC_FIELD_LEN))/(HAM_CACHE_MSG_DATA_LEN)) /**< The maximum number of cache message can be sent at once. */

/** @typedef ham_messaging_sys_task_params_t.
 *  @brief HAM Radio messaging system Task Params.
 *
 * Struct containing all the parameters that must be passed to the
 * task during the call to xTaskCreate.
 */
typedef struct {
    uint8_t id;                        /**< Task ID. */
    uint32_t task_period;              /**< Task Period (ms). */
    uint32_t ack_nack_delay_time;      /**< Time before sending the ACK or NACK packet (ms). */
    ttc_handle_t *ttc_handle;          /**< Handle for TTC generic parameters. */
    QueueHandle_t radio_tx_queue;      /**< Handle for the Radio TX Queue. */
    QueueHandle_t ham_packet_rx_queue; /**< Handle for the HAMRadio packet RX Queue. */
} ham_messaging_sys_task_params_t;

/** @typedef ham_packet_data_t.
 *  @brief HAM Radio packet data.
 *
 *  Struct containing the data of the HAM Radio packet.
 */
typedef struct {
    uint8_t ham_crc[HAM_CRC_LEN];                   /**< CRC of HAM Radio packet. */
    uint8_t command;                                /**< Commande type, 'a' for asking, 's' for sending and 'c' for get cache data. */
    uint8_t sender_callsign[HAM_CALL_SIGN_LEN];     /**< Sender callsign. */
    uint8_t recipient_callsign[HAM_CALL_SIGN_LEN];  /**< Recipient callsign. */
    uint8_t message[HAM_MAX_MSG_LEN];               /**< The user message. */
} ham_packet_data_t;

/** @typedef ham_packet_t.
 *  @brief HAM Radio packet.
 *
 *  Struct containing the data, the tag and the timestamp of the HAM Radio packet.
 */
typedef struct {
    uint8_t pkt_tag;                            /**< Packet tag 0 for erasable 1 for not sent 2 for sent. */
    uint32_t timestamp __attribute__((packed)); /**< Timestamp. */
    ham_packet_data_t data ;                    /**< Data of the HAM packet. */

} ham_packet_t;

/**
 *  @brief Ham Radio Messaging System Task main function.
 *  @param task_params Pointer to ham_messaging_sys_task_params_t.
 */
void ham_messaging_sys_task(void *task_params);

/**
 *  @brief Decrypt the given packet data and check its validity.
 *  @param data Pointer to packet data.
 *  @param data_len Data length.
 *  @param index_to_start Index of the data to start decrypting.
 *
 *  @return 0 if success, 1 if error.
 */
uint8_t decrypt_pkt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start);

/**
 *  @brief Encrypt the given packet data.
 *  @param data Pointer to packet data.
 *  @param data_len Data length.
 *  @param index_to_start Index of the data to start decrypting.
 */
void encrypt_pkt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start);

/**
 *  @brief Push the given radio packet to the tx queue.
 *  @param params Pointer to ham_messaging_sys_task_params_t.
 *  @param pkt_to_push Pointer to csp_packet_t.
 * 
 *  @return 0 if success, 1 if error.
 */
uint8_t push_pkt_to_radio_tx_queue(const ham_messaging_sys_task_params_t *params,
                                    const csp_packet_t *pkt_to_push);

/**
 *  @brief Build ACK or NACK csp packet from the given type and message.
 *  @param ack_nack_csp_pkt Pointer to csp_packet_t.
 *  @param src_pkt Pointer to csp_packet_t.
 *  @param type_code Type code of the packet, ACK or NACK.
 *  @param msg_code Message code off the ACK or NACK for identify the content.
 */
void build_ack_nack_csp_pkt(csp_packet_t *ack_nack_csp_pkt,const csp_packet_t *src_pkt,
                                const uint8_t type_code,const uint8_t msg_code);

/**
 *  @brief Build hamradio csp packet from the given data.
 *  @param ham_csp_pkt Pointer to ham_packet_t.
 *  @param data_to_send Pointer to csp_packet_t.
 *  @param src_pkt Pointer to csp_packet_t.
 */
void build_ham_csp_pkt(csp_packet_t *ham_csp_pkt,const ham_packet_t *data_to_send, const csp_packet_t *src_pkt);

/**
 *  @brief Build cache csp packet from the given data.
 *  @param cache_csp_pkt Pointer to ham_packet_t.
 *  @param src_pkt Pointer to csp_packet_t.
 *  @param data_to_send Pointer to the data to be send.
 *  @param data_len Length of the data to be send.
 *  @param cache_msg_num The number of cache message to be sent in the packet.
 */
void build_cache_csp_pkt(csp_packet_t *cache_csp_pkt,const csp_packet_t *src_pkt,
                                const uint8_t *data_to_send, const uint8_t data_len,const uint8_t cache_msg_num);

/**
 *  @brief Taking all the stored packets callsign, tag and timestamp from the eeprom and saving to the cache. Besides the packet count is calculated.
 *  @param ham_pkt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pkt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pkt_count Pointer to the hamradio packet count.
 */
void update_cache_from_eeprom(uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count);

/**
 *  @brief Check the tag of saved packets and compare the timestamps of those packets with the given delay, according to that packets tag is changed and re-saved if the delay has been reached. 
 *  @param params Pointer to ham_messaging_sys_task_params_t.
 *  @param ham_pkt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pkt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pkt_count Pointer to the hamradio packet count.
 */
void check_saved_msg_states(const ham_messaging_sys_task_params_t *params,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count);

/**
 *  @brief Check some conditions about the user and the packet sent then if those conditions are met, it saves the message. 
 *  @param params Pointer to ham_messaging_sys_task_params_t.
 *  @param rx_pkt Pointer to csp_packet_t
 *  @param ham_pkt Pointer to ham_packet_t.
 *  @param ham_pkt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pkt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pkt_count Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void handle_send_msg_cmd(const ham_messaging_sys_task_params_t *params,csp_packet_t *rx_pkt,ham_packet_t *ham_pkt,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count,const uint8_t debug);

/**
 *  @brief Check if there is a stored message for the person that made the request, if yes a HAM radio csp packet with the message is send to the person.
 *  @param params Pointer to ham_messaging_sys_task_params_t.
 *  @param rx_pkt Pointer to csp_packet_t
 *  @param ham_pkt Pointer to ham_packet_t.
 *  @param ham_pkt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pkt_timestamp_cache Array where timestamps are stored.
 *  @param debug Debug state.
 */
void handle_ask_msg_cmd(const ham_messaging_sys_task_params_t *params,csp_packet_t *rx_pkt,ham_packet_t *ham_pkt,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],const uint8_t debug);

/**
 *  @brief check if there is cache data to send, if yes sending all the data stored in the cache to the user.
 *  @param params Pointer to ham_messaging_sys_task_params_t.
 *  @param rx_pkt Pointer to csp_packet_t
 *  @param ham_pkt Pointer to ham_packet_t.
 *  @param ham_pkt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pkt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pkt_count Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void handle_get_cache_cmd(const ham_messaging_sys_task_params_t *params,const csp_packet_t *rx_pkt,const uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],const uint32_t ham_pkt_timestamp_cache[],const uint8_t ham_pkt_count,const uint8_t debug);

#endif
