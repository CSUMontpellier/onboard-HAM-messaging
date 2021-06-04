#include "unity.h"

#include "kernel/FreeRTOS.h"
#include "kernel/os_queue.h"
#include "kernel/os_task.h"

#include <stdlib.h>

#include "lib/csp_handler/libcsp_formatter.h"
#include "lib/libsrdb/R3A_Csp_Header.h"
#include <csp/csp_crc32.h>

#include "app/rob3u/ham_messaging_sys_task.h"
#include "app/rob3u/ttc_conf.h"
#include "app/rob3u/ttc_setup.h"
#include "hal/eeprom.h"

QueueHandle_t radio_tx_queue = NULL;
QueueHandle_t event_queue = NULL;
csp_packet_t *rx_packet = NULL;
csp_packet_t *packet_sent_from_ham = NULL;
csp_packet_t *ack_nack_csp_packet = NULL;
csp_packet_t *cache_csp_packet = NULL;
csp_packet_t *hamradio_csp_packet = NULL;

hamradio_message_t *hamradio_message = NULL;
hamradio_message_t *hamradio_message_ask_command = NULL;

ham_messaging_sys_task_params_t params;
ttc_handle_t ttc_handle;

uint8_t number_of_ack_nack_type_code = 2;
uint8_t number_of_ack_nack_msg_code = 7;
uint8_t rv;
static const uint8_t debug = 1;

void create_generic_csp_packet(csp_packet_t *csp_packet);
void create_generic_hamradio_message_t(hamradio_message_t *hamradio_message);
void create_hamradio_message_ask_command(hamradio_message_t *hamradio_msg);

void setUp(void) {
    csp_conf_t csp_conf;
    csp_conf_get_defaults(&csp_conf);
    csp_conf.buffer_data_size = TTC_CSP_BUFFER_DATA_SIZE;
    csp_conf.address = CSP_ADD_UHF;
    csp_conf.buffers = 10;
    int error = csp_init(&csp_conf);
    if(error != CSP_ERR_NONE) {
        exit(1);
    }
    /* Create Radio TX Queue. */
    radio_tx_queue = xQueueCreate(RADIO_TX_QUEUE_SIZE,     /* Queue length */
                                  sizeof(csp_packet_t *)); /* Queue item size */
    configASSERT(radio_tx_queue != NULL);

    params.ttc_handle = &ttc_handle;
    params.radio_tx_queue = radio_tx_queue;
    params.task_period = 1;
    params.ttc_handle->timestamp = 1618581400;

    /* Create csp packet that simulate a packet sent from user */
    rx_packet = csp_buffer_get(csp_buffer_data_size());
    create_generic_csp_packet(rx_packet);

    hamradio_message = (hamradio_message_t *)malloc(sizeof(hamradio_message_t));
    create_generic_hamradio_message_t(hamradio_message);

    hamradio_message_ask_command =
        (hamradio_message_t *)malloc(sizeof(hamradio_message_t));
    eeprom_init();

    packet_sent_from_ham = csp_buffer_get(csp_buffer_data_size());
}

void tearDown(void) {
}
void test_build_ack_nack_csp_packet(void) {
    ack_nack_csp_packet = csp_buffer_get(csp_buffer_data_size());
    /* When building ack/nack packet for every possible type and message the validity those packets is checked */
    for(uint8_t i = 0; i < number_of_ack_nack_type_code; i++) {
        for(uint8_t j = 0; j < number_of_ack_nack_msg_code; j++) {
            build_ack_nack_csp_packet(ack_nack_csp_packet, rx_packet,
                                      RADIO_ACK_CODE_ACK + i, MSG_STORED + j);
            TEST_ASSERT_EQUAL_UINT8(rx_packet->id.flags, ack_nack_csp_packet->id.flags);
            TEST_ASSERT_EQUAL_UINT8(rx_packet->id.src, ack_nack_csp_packet->id.dst);
            TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dst, ack_nack_csp_packet->id.src);
            TEST_ASSERT_EQUAL_UINT8(rx_packet->id.sport, ack_nack_csp_packet->id.dport);
            TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dport, ack_nack_csp_packet->id.sport);
            TEST_ASSERT_EQUAL_UINT8(0, ack_nack_csp_packet->id.pri);
            TEST_ASSERT_EQUAL_UINT8(HAM_RADIO_ACK_NACK_DATA_LEN,
                                    ack_nack_csp_packet->length);
            TEST_ASSERT_EQUAL_UINT8(RADIO_ACK_CODE_ACK + i, ack_nack_csp_packet->data[0]);
            TEST_ASSERT_EQUAL_UINT8(MSG_STORED + j, ack_nack_csp_packet->data[1]);
        }
    }
}

void test_encrypt_decrypt_radio_packet_data(void) {
    // TODO : test ham CRC ?
    uint8_t test_data[] = {'1', '2', '3', '4', '5', '6'};
    rx_packet->length = 6;
    /* Fill the rx packet data field with the test data */
    memcpy(rx_packet->data, test_data, rx_packet->length);
    /* Ecrypt and decrypt the data for testing the encryption/decryption functions */
    encrypt_radio_packet_data(rx_packet->data, rx_packet->length, HAM_CRC_LENGTH);
    decrypt_radio_packet_data(rx_packet->data, rx_packet->length, HAM_CRC_LENGTH);
    /* Check if the the test data is corrupted */
    TEST_ASSERT_EQUAL_CHAR_ARRAY(test_data, rx_packet->data, rx_packet->length);
}

void test_build_cache_csp_packet(void) {
    cache_csp_packet = csp_buffer_get(csp_buffer_data_size());
    /* Creat cache data */
    uint8_t cache_data_to_send[CACHE_MSG_DATA_LENGTH] = "1t2axxxg8txxx2222";
    uint8_t number_of_cache_msg = 1;
    /* Build cache csp packet with the given cache data */
    build_cache_csp_packet(cache_csp_packet, rx_packet, cache_data_to_send,
                           (CACHE_MSG_DATA_LENGTH * number_of_cache_msg),
                           number_of_cache_msg);
    /* Check the ids of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.flags, cache_csp_packet->id.flags);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.src, cache_csp_packet->id.dst);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dst, cache_csp_packet->id.src);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.sport, cache_csp_packet->id.dport);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dport, cache_csp_packet->id.sport);
    TEST_ASSERT_EQUAL_UINT8(0, cache_csp_packet->id.pri);
    /* Check the length of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(CACHE_MSG_DATA_LENGTH + number_of_cache_msg,
                            cache_csp_packet->length);
    /* Check the number of cache msg of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(number_of_cache_msg, cache_csp_packet->data[0]);
    /* Check cahce datas of the builded packet */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(
        cache_data_to_send, &cache_csp_packet->data[1], CACHE_MSG_DATA_LENGTH);
}

void test_build_hamradio_csp_packet(void) {
    hamradio_csp_packet = csp_buffer_get(csp_buffer_data_size());
    /* Build a ham radio csp packet from the given message */
    build_hamradio_csp_packet(hamradio_csp_packet, hamradio_message, rx_packet);
    /* Check the ids of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.flags, hamradio_csp_packet->id.flags);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.src, hamradio_csp_packet->id.dst);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dst, hamradio_csp_packet->id.src);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.sport, hamradio_csp_packet->id.dport);
    TEST_ASSERT_EQUAL_UINT8(rx_packet->id.dport, hamradio_csp_packet->id.sport);
    TEST_ASSERT_EQUAL_UINT8(0, hamradio_csp_packet->id.pri);
    /* Check the length of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(hamradio_csp_packet->length, strlen(hamradio_message));
    /* Decrypt and check if the message is correct */
    decrypt_radio_packet_data(hamradio_csp_packet->data, hamradio_csp_packet->length,
                              (TAG_LENGTH + HAM_CRC_LENGTH + TIMESTAMP_LENGTH));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(hamradio_csp_packet->data, hamradio_message,
                                  hamradio_csp_packet->length);
}

void test_push_packet_to_radio_tx_queue(void) {
    /* Send packet to radio TX Queue  */
    rv = push_packet_to_radio_tx_queue(&params, hamradio_csp_packet);
    TEST_ASSERT_EQUAL_UINT8(0, rv);
    /* Check if a packet was enqueued to radio TX Queue */
    rv = uxQueueMessagesWaiting(radio_tx_queue);
    TEST_ASSERT_EQUAL_UINT8(1, rv);
}

void test_eeprom_get_ham_messages(void) {
    /* For storing the tag, the recipient and sender callsign statically. */
    uint8_t hamradio_message_cache[MAX_MESSAGE_NUMBER][(2 * CALL_SIGN_LENGTH) + TAG_LENGTH] = {0};
    /* For storing the timestamp of messages statically. */
    uint32_t hamradio_message_timestamp_cache[MAX_MESSAGE_NUMBER] = {0};
    uint8_t hamradio_message_count = 0;
    /* Store a test message in the eeprom. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, hamradio_message, sizeof(hamradio_message_t));
    /* Get the needed message data from the eeprom to the cache. */
    eeprom_get_ham_messages(hamradio_message_cache, hamradio_message_timestamp_cache,
                            &hamradio_message_count);
    /* Check the message count */
    TEST_ASSERT_EQUAL_UINT8(1, hamradio_message_count);
    /* Check the tag, timestamp, sender and recipient callsign. */
    TEST_ASSERT_EQUAL_UINT32(hamradio_message->timestamp,
                             hamradio_message_timestamp_cache[0]);
    TEST_ASSERT_EQUAL_UINT8(hamradio_message->message_tag, hamradio_message_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(hamradio_message->data.recipient_callsign,
                                  &hamradio_message_cache[0][1], CALL_SIGN_LENGTH);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(hamradio_message->data.sender_callsign,
                                  &hamradio_message_cache[0][7], CALL_SIGN_LENGTH);
}

void test_check_saved_messages_states(void) {
    /* For storing the tag, the recipient and sender callsign statically. */
    uint8_t hamradio_message_cache[MAX_MESSAGE_NUMBER][(2 * CALL_SIGN_LENGTH) + TAG_LENGTH] = {0};
    /* For storing the timestamp of messages statically. */
    uint32_t hamradio_message_timestamp_cache[MAX_MESSAGE_NUMBER] = {0};
    uint8_t hamradio_message_count = 0;
    /* Change the default timestamp of the message. */
    hamradio_message->timestamp = params.ttc_handle->timestamp;
    /* Store a test message in the eeprom, the default tag is MSG_NOT_SENT. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, hamradio_message, sizeof(hamradio_message_t));
    /* Store a second test message in the eeprom, with the MSG_SENT_TAG tag. */
    hamradio_message->message_tag = MSG_SENT_TAG;
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR + 1, hamradio_message,
                            sizeof(hamradio_message_t));
    /* Get the needed message data from the eeprom to the cache. */
    eeprom_get_ham_messages(hamradio_message_cache, hamradio_message_timestamp_cache,
                            &hamradio_message_count);
    /* Increase the timestamp of the ttc_handle by the value SENT_MSG_DELAY. */
    params.ttc_handle->timestamp = params.ttc_handle->timestamp + SENT_MSG_DELAY;
    /* Run the function and check the state of each message */
    check_saved_messages_states(&params, hamradio_message_cache,
                                hamradio_message_timestamp_cache, &hamradio_message_count);
    TEST_ASSERT_EQUAL_UINT8(MSG_NOT_SENT_TAG, hamradio_message_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8(MSG_ERASABLE_TAG, hamradio_message_cache[1][0]);
    /* Decrease for setting the timestamp the his initial value and increase the timestamp of the ttc_handle by the value NOT_SENT_MSG_DELAY. */
    params.ttc_handle->timestamp =
        params.ttc_handle->timestamp - SENT_MSG_DELAY + NOT_SENT_MSG_DELAY;
    /* Run the function and check the state of each message */
    check_saved_messages_states(&params, hamradio_message_cache,
                                hamradio_message_timestamp_cache, &hamradio_message_count);
    TEST_ASSERT_EQUAL_UINT8(MSG_ERASABLE_TAG, hamradio_message_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8(MSG_ERASABLE_TAG, hamradio_message_cache[1][0]);
}

void test_handle_send_message_command(void) {
    uint8_t hamradio_message_cache[MAX_MESSAGE_NUMBER][(2 * CALL_SIGN_LENGTH) + TAG_LENGTH] = {0};
    /* For storing the timestamp of messages statically. */
    uint32_t hamradio_message_timestamp_cache[MAX_MESSAGE_NUMBER] = {0};
    uint8_t hamradio_message_count = 0;
    hamradio_message_t *hamradio_message_eeprom = NULL;
    hamradio_message_eeprom = (hamradio_message_t *)malloc(sizeof(hamradio_message_t));
    /* Get the needed message data from the eeprom to the cache. */
    eeprom_get_ham_messages(hamradio_message_cache, hamradio_message_timestamp_cache,
                            &hamradio_message_count);
    /* Set the command type of the message to send. */
    hamradio_message->data.command = 's';
    /* Run the function. */
    handle_send_message_command(
        &params, rx_packet, hamradio_message, hamradio_message_cache,
        hamradio_message_timestamp_cache, &hamradio_message_count, debug);
    /* Read the processed message from the eeprom and check if it is correct. */
    eeprom_read_byte_array(HAM_MSG_EEPROM_ADDR, hamradio_message_eeprom,
                           sizeof(hamradio_message_t));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(hamradio_message, hamradio_message_eeprom,
                                  strlen(hamradio_message));
}

void test_handle_ask_message_command(void) {
    uint8_t hamradio_message_cache[MAX_MESSAGE_NUMBER][(2 * CALL_SIGN_LENGTH) + TAG_LENGTH] = {0};
    /* For storing the timestamp of messages statically. */
    uint32_t hamradio_message_timestamp_cache[MAX_MESSAGE_NUMBER] = {0};
    uint8_t hamradio_message_count = 0;
    /* Get the needed message data from the eeprom to the cache. */
    eeprom_get_ham_messages(hamradio_message_cache, hamradio_message_timestamp_cache,
                            &hamradio_message_count);
    /* Creat a packet with ask command type.  */
    create_hamradio_message_ask_command(hamradio_message_ask_command);
    /* Change the default timestamp of the message. */
    hamradio_message_ask_command->timestamp = params.ttc_handle->timestamp;
    hamradio_message->timestamp = params.ttc_handle->timestamp;
    hamradio_message->data.command = 's';
    /* Run the function. */
    handle_ask_message_command(&params, rx_packet, hamradio_message_ask_command,
                               hamradio_message_cache,
                               hamradio_message_timestamp_cache, debug);
    /* Dequeue packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &packet_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Decrypt the data part of the packe without including the crc, tag and timestamp. */
    decrypt_radio_packet_data(packet_sent_from_ham->data, packet_sent_from_ham->length,
                              HAM_CRC_LENGTH + TAG_LENGTH + TIMESTAMP_LENGTH);
    /* Check if the data part is correct. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(packet_sent_from_ham->data, hamradio_message,
                                  strlen(hamradio_message));
}

void test_handle_get_cache_command(void) {
    uint8_t hamradio_message_cache[MAX_MESSAGE_NUMBER][(2 * CALL_SIGN_LENGTH) + TAG_LENGTH] = {0};
    /* For storing the timestamp of messages statically. */
    uint32_t hamradio_message_timestamp_cache[MAX_MESSAGE_NUMBER] = {0};
    uint8_t hamradio_message_count = 0;
    /* Get the needed message data from the eeprom to the cache. */
    eeprom_get_ham_messages(hamradio_message_cache, hamradio_message_timestamp_cache,
                            &hamradio_message_count);
    /* Run the function. */
    handle_get_cache_command(&params, rx_packet, hamradio_message_cache,
                             hamradio_message_timestamp_cache,
                             hamradio_message_count, debug);
    /* Dequeue packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &packet_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the number of cache msg created who is in the first byte of the data part. */
    TEST_ASSERT_EQUAL_UINT8(packet_sent_from_ham->data[0], 1);
    /* Check the tag and callsigns. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(&packet_sent_from_ham->data[1],
                                  &hamradio_message_cache[0][0], 13);
    /* Check the timestamp. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(&packet_sent_from_ham->data[14],
                                  &hamradio_message_timestamp_cache[0], 4);
}

void create_generic_csp_packet(csp_packet_t *csp_packet) {
    /* Creat a csp packet with id appropriate to the HAM radio system task */
    csp_packet->id.flags = CSP_FCRC32;
    csp_packet->id.sport = 0x01;
    csp_packet->id.dport = 0x01;
    csp_packet->id.src = 0x1D;
    csp_packet->id.dst = 0x09;
    csp_packet->id.pri = 0x02;
}

void create_generic_hamradio_message_t(hamradio_message_t *hamradio_msg) {
    /* Creat a ham radio message with a tag,timestamp,crc,command,sender callsign,recipient callsign and message to send */
    uint8_t ham_test_message[25] = {1,   '2', '2', '2', '2', '3', '3', '4', '5',
                                    '5', '5', '5', '5', '5', '6', '6', '6', '6',
                                    '6', '6', '7', '7', '7', '7', '7'};
    memcpy(hamradio_message, ham_test_message, 25);
}

void create_hamradio_message_ask_command(hamradio_message_t *hamradio_msg) {
    memcpy(hamradio_msg, hamradio_message, 25);
    memcpy(hamradio_msg->data.sender_callsign,
           hamradio_message->data.recipient_callsign, CALL_SIGN_LENGTH);
    hamradio_msg->data.command = 'a';
}