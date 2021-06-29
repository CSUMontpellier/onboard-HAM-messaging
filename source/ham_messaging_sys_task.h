/** @file ham_messaging_sys_task.h
 *  @brief HAM Radio Messaging System Task Header.
 */

#ifndef HAM_MESSAGING_SYS_TASK_H
#define HAM_MESSAGING_SYS_TASK_H

#include "app/rob3u/ttc_setup.h"

#define HAM_MAX_MSG_NBR 20U                /**< Maximum number of storable messages. */
#define HAM_ALLOWED_MSG_NBR 1U             /**< The maximum allowed number of storable message per person. */
#define HAM_SENT_MSG_DELAY 10U             /**< The time given before deleting messages with the sent tag in second. */
#define HAM_NOT_SENT_MSG_DELAY 60U         /**< The time given before deleting messages with the not sent tag in second. */
#define HAM_MAX_MSG_LEN 20U                /**< The maximum length of the message. */
#define HAM_TAG_LEN 1U                     /**< Packet tag length. */
#define HAM_CRC_LEN 2U                     /**< HAM_CRC_length. */
#define HAM_CALL_SIGN_LEN 6U               /**< The length of the the call sign. */
#define HAM_TIMESTAMP_LEN 4U               /**< Packet timestamp length. */
#define HAM_ACK_NACK_PCKT_LEN 2U           /**< The data lengt of the ACK/NACK packet. */
#define HAM_PWD_LEN 6U                     /**< The length of admin password. */
#define HAM_MSG_MAX_DELAY_LEN 6U           /**< The maximum length of messages delay value. */
#define HAM_ADMIN_PCKT_DATA_LEN 12U        /**< The length of the admin packet data field. */
#define HAM_MSG_EEPROM_ADDR 0U             /**< Eeprom starting addres of the saved packet. */
#define HAM_PWD_ADDR 21U                   /**< Eeprom starting addres of the saved password. */
#define HAM_SENT_MSG_DELAY_ADDR 22U        /**< Eeprom starting addres of the sent message delay value. */
#define HAM_NOT_SENT_MSG_DELAY_ADDR 23U    /**< Eeprom starting addres of the not sent message delay value. */
#define HAM_PCKT_CMD_TYPE_INDEX 2U         /**< The index number of the byte representing the command type. */
#define HAM_ID_LEN ((2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN) /**< The length of the id part, that include the tag length, the recipient and sender call sign length.. */
#define HAM_CACHE_MSG_DATA_LEN (uint8_t)((HAM_CALL_SIGN_LEN*2)+(HAM_TAG_LEN)+(HAM_TIMESTAMP_LEN)) /**< The total length of the data saved in the cache for one ham raio packet. */
#define HAM_MAX_CACHE_MSG_NBR (uint8_t)(((TTC_CSP_BUFFER_DATA_SIZE)-(TTC_CSP_CRC_FIELD_LEN))/(HAM_CACHE_MSG_DATA_LEN)) /**< The maximum number of cache message can be sent at once. */

/** @typedef ham_msg_sys_task_params_t.
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
} ham_msg_sys_task_params_t;

/** @typedef ham_user_pckt_data_t.
 *  @brief HAM Radio user packet data.
 *
 *  Struct containing the data of the HAM Radio packet used from general user.
 */
typedef struct {
    uint8_t ham_crc[HAM_CRC_LEN];                   /**< CRC of HAM Radio packet. */
    uint8_t command_type;                           /**< Commande type. */
    uint8_t command;                                /**< Commande. */
    uint8_t sender_callsign[HAM_CALL_SIGN_LEN];     /**< Sender callsign. */
    uint8_t recipient_callsign[HAM_CALL_SIGN_LEN];  /**< Recipient callsign. */
    uint8_t message[HAM_MAX_MSG_LEN];               /**< The user message. */
} ham_user_pckt_data_t;

/** @typedef ham_user_packet_t.
 *  @brief HAM Radio user packet.
 *
 *  Struct containing the data, the tag and the timestamp of the HAM Radio user packet.
 */
typedef struct {
    uint8_t tag;                                /**< Packet tag. */
    uint32_t timestamp __attribute__((packed)); /**< Timestamp. */
    ham_user_pckt_data_t data ;                 /**< Data of the HAM user packet. */
} ham_user_packet_t;

/** @typedef ham_admin_packet_t.
 *  @brief HAM Radio admin packet data.
 *
 *  Struct containing the data of the HAM Radio packet used from admin.
 */

typedef struct {
    uint8_t ham_crc[HAM_CRC_LEN];                   /**< CRC of HAM Radio packet. */
    uint8_t command_type;                           /**< Commande type. */
    uint8_t command;                                /**< Commande. */
    uint8_t pwd[HAM_PWD_LEN];                       /**< Password. */
    uint8_t data[HAM_ADMIN_PCKT_DATA_LEN];          /**< Data of the HAM admin packet. */
} ham_admin_packet_t;

/** @typedef ham_msg_delay_t.
 *  @brief HAM Radio message delay time.
 *
 *  Struct containing the delay time of messages. The delay time is the time to wait before deleting the message.
 */
typedef struct {
    uint32_t sent_msg;     /**< The time given before deleting messages with the sent tag in second. */
    uint32_t not_sent_msg; /**< The time given before deleting messages with the not sent tag in second. */
} ham_msg_delay_t;

/** @typedef ham_command_t.
 *  @brief HAM Radio commands.
 *
 *  Enum containing available HAM radio commands.
 */
typedef enum {
    HAM_SEND_MSG_CMD = 's',                 /**< Byte to identify the send message command. */
    HAM_ASK_MSG_CMD = 'a',                  /**< Byte to identify the ask message command. */
    HAM_GET_CACHE_CMD = 'c',                /**< Byte to identify the get cache data command. */
    HAM_DEL_ALL_MSG_CMD = 'd',              /**< Byte to identify the delete all messages command. */
    HAM_UPD_NOT_SENT_MSG_DELAY_CMD = 'n',   /**< Byte to identify the update not sent message delay command. */
    HAM_UPD_SENT_MSG_DELAY_CMD = 't',       /**< Byte to identify the update not sent message delay command. */
    HAM_UPD_PWD_CMD = 'p',                  /**< Byte to identify the update password command. */
}ham_command_t;

/** @typedef ham_command_type_t.
 *  @brief HAM Radio command types.
 *
 *  Enum containing available HAM radio command types.
 */
typedef enum {
    HAM_ADMIN_CMD = 'a',                 /**< Byte to identify the admind commands. */
    HAM_USER_CMD = 'u',                  /**< Byte to identify the user commands. */
}ham_command_type_t;

/** @typedef ham_tag_t.
 *  @brief HAM Radio packet tag.
 *
 *  Enum containing Ham Radio tags.
 */
typedef enum {
    HAM_MSG_ERASABLE_TAG  = 0x00,        /**< Tag of the packet indicating that it can be replaced by another packet. */
    HAM_MSG_NOT_SENT_TAG = 0x01,         /**< Tag of the packet indicating that it was not sent. */
    HAM_MSG_SENT_TAG = 0x02,             /**< Tag of the packet indicating that it was sent. */
}ham_tag_t;

/** @typedef ham_nack_msg_code_t.
 *  @brief Nack message codes.
 *
 *  Enum containing nack message codes.
 */
typedef enum {
    HAM_INV_CMD = 0x08,                  /**< NACK message code that saying that the command is invalid. */
    HAM_MAX_MSG_NBR_REACHED = 0x09,      /**< NACK message code that saying that the storable maximum message number has been reached. */
    HAM_INV_CRC = 0x0A,                  /**< NACK message code that saying that the HAM CRC is invalid. */
    HAM_NO_MSG = 0x0B,                   /**< NACK message code that saying that there is no message for the given call sign. */
    HAM_MAX_MSG_LEN_EXCEED = 0x0C,       /**< NACK message code that saying that the the maximum length of the message exceeded. */
    HAM_ALLOWED_MSG_NBR_REACHED = 0x0D,  /**< NACK message code that saying that the maximum allowed number of storable message per person has been reached. */
    HAM_NO_SAVED_MSG = 0x0E,             /**< NACK message code that saying that there are no saved messages. */
    HAM_INV_CMD_TYPE = 0x0F,             /**< NACK message code that saying that the command type is invalid. */
    HAM_INV_PWD = 0x10,                  /**< NACK message code that saying that the password is invalid. */
    HAM_PWD_NOT_EQ = 0x11,               /**< NACK message code that saying that the password in the double confirmation is not the same as each other. */
    HAM_MSG_MAX_DELAY_LEN_EXCEED = 0x12, /**< NACK message code that saying the length of the delay value sent from user is to long. */
}ham_nack_msg_code_t;

/** @typedef ham_ack_msg_code_t.
 *  @brief Ack message codes.
 *
 *  Enum containing ack message codes.
 */
typedef enum {
    HAM_MSG_STORED = 0x03,               /**< ACK message code saying that the message is stored. */
    HAM_NOT_SENT_MSG_DELAY_UPD = 0x04,   /**< ACK message code saying that the delay value for not sent messages is updated successfully. */
    HAM_SENT_MSG_DELAY_UPD = 0x05,       /**< ACK message code saying that the delay value for sent messages is updated successfully. */
    HAM_ALL_MSG_DELETED = 0x06,          /**< ACK message code saying that all saved messages are deleted. */
    HAM_PWD_CHANGED = 0x07,              /**< ACK message code saying that the admin password is changed. */
}ham_ack_msg_code_t;

/**
 *  @brief Ham Radio Messaging System Task main function.
 *  @param task_params Pointer to ham_msg_sys_task_params_t.
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
uint8_t ham_decrypt_pckt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start);

/**
 *  @brief Encrypt the given packet data.
 *  @param data Pointer to packet data.
 *  @param data_len Data length.
 *  @param index_to_start Index of the data to start decrypting.
 */
void ham_encrypt_pckt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start);

/**
 *  @brief Build ACK or NACK csp packet from the given type and message.
 *  @param ack_nack_csp_pckt Pointer to csp_packet_t.
 *  @param src_pckt_id Pointer to csp_id_t.
 *  @param type_code Type code of the packet, ACK or NACK.
 *  @param msg_code Message code off the ACK or NACK for identify the content.
 */
void ham_build_ack_nack_csp_pckt(csp_packet_t *ack_nack_csp_pckt,const csp_id_t *src_pckt_id,
                                const uint8_t type_code,const uint8_t msg_code);

/**
 *  @brief Build hamradio csp packet from the given data.
 *  @param ham_csp_pckt Pointer to ham_user_packet_t.
 *  @param data_to_send Pointer to csp_packet_t.
 *  @param src_pckt_id Pointer to csp_id_t.
 */
void ham_build_ham_csp_pckt(csp_packet_t *ham_csp_pckt,const ham_user_packet_t *data_to_send, const csp_id_t *src_pckt_id);

/**
 *  @brief Build cache csp packet from the given data.
 *  @param cache_csp_pckt Pointer to csp_packet_t.
 *  @param src_pckt_id Pointer to csp_id_t.
 *  @param data_to_send Pointer to the data to be send.
 *  @param data_len Length of the data to be send.
 *  @param cache_msg_nbr The number of cache message to be sent in the packet.
 */
void ham_build_cache_csp_pckt(csp_packet_t *cache_csp_pckt,const csp_id_t *src_pckt_id,
                                const uint8_t *data_to_send, const uint8_t data_len,const uint8_t cache_msg_nbr);

/**
 *  @brief Taking all the stored packets callsign, tag and timestamp from the eeprom and saving to the cache. Besides the packet count is calculated, the admin password and messages delay is retrieved.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param pwd Array where the passwordis stored.
 *  @param msg_delay Pointer to ham_msg_delay_t.
 */
void ham_update_data_from_eeprom(uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt,uint8_t pwd[],ham_msg_delay_t *msg_delay);

/**
 *  @brief Check the tag of saved packets and compare the timestamps of those packets with the given delay, according to that packets tag is changed and re-saved if the delay has been reached. 
 *  @param params Pointer to ham_msg_sys_task_params_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param msg_delay Pointer to ham_msg_delay_t.
 */
void ham_check_saved_msg_states(const ttc_handle_t *ttc_handle,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],const uint32_t ham_pckt_timestamp_cache[],const ham_msg_delay_t *msg_delay,uint8_t *ham_pckt_cnt);

/**
 *  @brief Check some conditions about the user and the packet sent then if those conditions are met, it saves the message. 
 *  @param params Pointer to ham_msg_sys_task_params_t.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void ham_handle_send_msg_cmd(const ham_msg_sys_task_params_t *params,const csp_id_t *rx_pckt_id,ham_user_packet_t *ham_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt, uint8_t debug);

/**
 *  @brief Check if there is a stored message for the person that made the request, if yes a HAM radio csp packet with the message is send to the person.
 *  @param params Pointer to ham_msg_sys_task_params_t.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param debug Debug state.
 */
void ham_handle_ask_msg_cmd(const ham_msg_sys_task_params_t *params,const csp_id_t *rx_pckt_id,const ham_user_packet_t *ham_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[], uint8_t debug);

/**
 *  @brief check if there is cache data to send, if yes sending all the data stored in the cache to the user(timestamp,call signs,tag).
 *  @param @param radio_tx_queue The handle of the radio TX queue.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void ham_handle_get_cache_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,const uint8_t ham_pckt_id_cache[][HAM_ID_LEN],const uint32_t ham_pckt_timestamp_cache[],const uint8_t ham_pckt_cnt, uint8_t debug);


/**
 *  @brief Change the value of the delay used for not sent messages.
 *  @param radio_tx_queue The handle of the radio TX queue.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param msg_delay Pointer to the delay value.
 *  @param debug Debug state.
 */
void ham_handle_upd_not_sent_msg_delay_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint32_t *msg_delay,uint8_t debug);

/**
 *  @brief Change the value of the delay used for sent messages.
 *  @param radio_tx_queue The handle of the radio TX queue.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param msg_delay Pointer to the delay value.
 *  @param debug Debug state.
 */
void ham_handle_upd_sent_msg_delay_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint32_t *msg_delay,uint8_t debug);

/**
 *  @brief Delete all the saved messages.
 *  @param radio_tx_queue The handle of the radio TX queue.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void ham_handle_del_all_msg_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint8_t *ham_pckt_cnt,uint8_t debug);

/**
 *  @brief Change the initial password with the new password sent.
 *  @param radio_tx_queue The handle of the radio TX queue.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt Pointer to ham_user_packet_t.
 *  @param pwd Array where the passwordis stored.
 *  @param debug Debug state.
 */
void ham_handle_upd_pwd_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint8_t pwd[],uint8_t debug);

/**
 *  @brief Handle the commands sent from general users.
 *  @param params Pointer to ham_msg_sys_task_params_t.
 *  @param rx_pckt Pointer to csp_packet_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param debug Debug state.
 */
void ham_handle_user_cmd(const ham_msg_sys_task_params_t *params,const csp_packet_t *rx_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt,uint8_t debug);

/**
 *  @brief Handle the commands sent from admin.
 *  @param params Pointer to ham_msg_sys_task_params_t.
 *  @param rx_pckt_id Pointer to csp_id_t.
 *  @param ham_pckt_id_cache Array where the tags and call signs are stored.
 *  @param ham_pckt_timestamp_cache Array where timestamps are stored.
 *  @param ham_pckt_cnt Pointer to the hamradio packet count.
 *  @param msg_delay Pointer to the delay value.
 *  @param pwd Array where the passwordis stored.
 *  @param debug Debug state.
 */
void ham_handle_admin_cmd(const ham_msg_sys_task_params_t *params,const csp_packet_t *rx_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint8_t *ham_pckt_cnt,ham_msg_delay_t *msg_delay,uint8_t pwd[],uint8_t debug);

#endif
