#include "unity.h"

#include "os/FreeRTOS.h"
#include "os/os_queue.h"
#include "os/os_task.h"

#include <stdlib.h>

#include "libs/csp_handler/libcsp_formatter.h"
#include "libs/libsrdb/libsrdb_config.h"

#include "app/rob3u/ham_messaging_sys_task.h"
#include "app/rob3u/ttc_conf.h"
#include "app/rob3u/ttc_setup.h"
#include "hal/eeprom.h"
#include <app/rob3u/csum_packet_processing_task.h>
#include <csp/csp_crc32.h>

QueueHandle_t radio_tx_queue = NULL;
extern QueueHandle_t event_queue;
ham_user_packet_t *ham_user_pckt = NULL;
ham_admin_packet_t *ham_admin_pckt = NULL;
static csp_packet_t *rx_pckt = NULL;
csp_packet_t *pckt_sent_from_ham = NULL;

ham_msg_sys_task_params_t params;
ttc_handle_t ttc_handle;

uint8_t nbr_of_ack_nack_type_code = 2;
uint8_t nbr_of_ack_nack_msg_code = 7;
uint8_t rv;
const uint8_t debug = 1;
extern uint8_t admin_pwd[];

void fill_generic_csp_pckt_header(csp_packet_t *csp_pckt);
void fill_generic_ham_user_pckt(ham_user_packet_t *ham_user_pckt);
void create_ham_ask_msg_cmd(ham_user_packet_t *ham_user_pckt);
void fill_generic_ham_admin_pckt(ham_admin_packet_t *ham_admin_pckt);

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

    eeprom_init();

    /* Create and fill user packet. */
    ham_user_pckt = (ham_user_packet_t *)pvPortMalloc(sizeof(ham_user_packet_t));
    fill_generic_ham_user_pckt(ham_user_pckt);

    /* Creat ans fill admin packet. */
    ham_admin_pckt = (ham_admin_packet_t *)pvPortMalloc(sizeof(ham_admin_packet_t));
    fill_generic_ham_admin_pckt(ham_admin_pckt);

    /* Create and fill the header of the csp packet that simulate a packet sent from user. */
    rx_pckt = csp_buffer_get(csp_buffer_data_size());
    fill_generic_csp_pckt_header(rx_pckt);

    /* Create a packet for receiving the packet sent from ham radio over the queue. */
    pckt_sent_from_ham = csp_buffer_get(csp_buffer_data_size());
}

void tearDown(void) {
}

void test_ham_build_ack_nack_csp_pckt(void) {
    /* Creat a csp packet for ack/nack. */
    csp_packet_t *ack_nack_csp_pckt = NULL;
    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());

    /* Building ack/nack packet for every possible type and message code and checking the validity of those packets. */
    for(uint8_t i = 0; i < nbr_of_ack_nack_type_code; i++) {
        for(uint8_t j = 0; j < nbr_of_ack_nack_msg_code; j++) {
            ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt, &(rx_pckt->id),
                                        RADIO_ACK_CODE_ACK + i, HAM_MSG_STORED + j);

            TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.flags, ack_nack_csp_pckt->id.flags);
            TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.src, ack_nack_csp_pckt->id.dst);
            TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dst, ack_nack_csp_pckt->id.src);
            TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.sport, ack_nack_csp_pckt->id.dport);
            TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dport, ack_nack_csp_pckt->id.sport);
            TEST_ASSERT_EQUAL_UINT8(0, ack_nack_csp_pckt->id.pri);
            TEST_ASSERT_EQUAL_UINT8(HAM_ACK_NACK_PCKT_LEN, ack_nack_csp_pckt->length);
            TEST_ASSERT_EQUAL_UINT8(RADIO_ACK_CODE_ACK + i, ack_nack_csp_pckt->data[0]);
            TEST_ASSERT_EQUAL_UINT8(HAM_MSG_STORED + j, ack_nack_csp_pckt->data[1]);
        }
    }

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
    csp_buffer_free(ack_nack_csp_pckt);
}

void test_ham_encrypt_decrypt_pckt_data(void) {
    /* Creat test data. */
    uint8_t test_data[6] = {'1', '2', '3', '4', '5', '6'};
    rx_pckt->length = 6;

    /* Fill the rx packet data field with the test data. */
    memcpy(rx_pckt->data, test_data, rx_pckt->length);

    /* Ecrypt and decrypt the data for testing the encryption/decryption functions. */
    ham_encrypt_pckt_data(rx_pckt->data, rx_pckt->length, HAM_CRC_LEN);
    ham_decrypt_pckt_data(rx_pckt->data, rx_pckt->length, HAM_CRC_LEN);

    /* Check if the the test data is corrupted or not. */
    TEST_ASSERT_EQUAL_CHAR_ARRAY(test_data, rx_pckt->data, rx_pckt->length);

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
}

void test_ham_build_cache_csp_pckt(void) {
    /* Creat a csp packet to build csp packet containing cache data. */
    csp_packet_t *cache_csp_pckt = NULL;
    cache_csp_pckt = csp_buffer_get(csp_buffer_data_size());
    /* Creat cache data to send. */
    uint8_t cache_data_to_send[HAM_CACHE_MSG_DATA_LEN] = "1t2axxxg8txxx2222";
    /* Variable that representing the number of packets used when the cache data to send array was created. */
    uint8_t nbr_of_cache_msg = 1;

    /* Build cache csp packet with the given cache data. */
    ham_build_cache_csp_pckt(cache_csp_pckt, &(rx_pckt->id), cache_data_to_send,
                             (HAM_CACHE_MSG_DATA_LEN * nbr_of_cache_msg), nbr_of_cache_msg);

    /* Check the ids of the builded packet */
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.flags, cache_csp_pckt->id.flags);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.src, cache_csp_pckt->id.dst);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dst, cache_csp_pckt->id.src);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.sport, cache_csp_pckt->id.dport);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dport, cache_csp_pckt->id.sport);
    TEST_ASSERT_EQUAL_UINT8(0, cache_csp_pckt->id.pri);

    /* Check the length of the builded packet. */
    TEST_ASSERT_EQUAL_UINT8(HAM_CACHE_MSG_DATA_LEN + nbr_of_cache_msg,
                            cache_csp_pckt->length);

    /* Check the number of cache msg of the builded packet. */
    TEST_ASSERT_EQUAL_UINT8(nbr_of_cache_msg, cache_csp_pckt->data[0]);

    /* Check cache datas of the builded packet. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(cache_data_to_send, &cache_csp_pckt->data[1],
                                  HAM_CACHE_MSG_DATA_LEN);

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
    csp_buffer_free(cache_csp_pckt);
}

void test_ham_build_ham_csp_pckt(void) {
    /* Creat csp packet that will store a ham radio csp packet. */
    csp_packet_t *ham_csp_pckt = NULL;
    ham_csp_pckt = csp_buffer_get(csp_buffer_data_size());

    /* Build a ham radio csp packet from the given ham user packet. */
    ham_build_ham_csp_pckt(ham_csp_pckt, ham_user_pckt, &(rx_pckt->id));

    /* Check the ids of the builded packet. */
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.flags, ham_csp_pckt->id.flags);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.src, ham_csp_pckt->id.dst);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dst, ham_csp_pckt->id.src);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.sport, ham_csp_pckt->id.dport);
    TEST_ASSERT_EQUAL_UINT8(rx_pckt->id.dport, ham_csp_pckt->id.sport);
    TEST_ASSERT_EQUAL_UINT8(0, ham_csp_pckt->id.pri);

    /* Check the length of the builded packet. */
    TEST_ASSERT_EQUAL_UINT8(ham_csp_pckt->length, strlen((char *)ham_user_pckt));

    /* Decrypt and check if the message is correct. */
    ham_decrypt_pckt_data(ham_csp_pckt->data, ham_csp_pckt->length,
                          (HAM_TAG_LEN + HAM_CRC_LEN + HAM_TIMESTAMP_LEN));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ham_csp_pckt->data, ham_user_pckt,
                                  ham_csp_pckt->length);

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
    csp_buffer_free(ham_csp_pckt);
}

void test_push_packet_to_radio_tx_queue(void) {
    /* Creat csp packet that will store a ham radio packet. */
    csp_packet_t *ham_csp_pckt = NULL;
    ham_csp_pckt = csp_buffer_get(csp_buffer_data_size());

    /* Send packet to radio TX Queue.  */
    push_packet_to_radio_tx_queue(ham_csp_pckt, params.radio_tx_queue);
    rv = uxQueueMessagesWaiting(radio_tx_queue);
    TEST_ASSERT_EQUAL_UINT8(1, rv);

    /* Check if a packet was enqueued to radio TX Queue. */
    rv = uxQueueMessagesWaiting(radio_tx_queue);
    TEST_ASSERT_EQUAL_UINT8(1, rv);
}

void test_ham_update_data_from_eeprom(void) {
    /* Creat empty ham user packet for clearing the eeprom. */
    ham_user_packet_t ham_pckt_eeprom = {0};
    /* Initialize the delays time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};
    /* Creat a different password from the initial password for saving it in the eeprom. */
    uint8_t test_pwd[] = {'8', '7', '3', '4', '5', '4'};
    /* Creat a different delay values from the initial delay values for saving them in the eeprom. */
    uint32_t sent_test_delay = 60;
    uint32_t not_sent_test_delay = 200;
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of messages statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;

    /* Store a test message in the eeprom. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, (uint8_t *)ham_user_pckt,
                            sizeof(ham_user_packet_t));

    /* Store the created test values. */
    eeprom_write_byte_array(HAM_PWD_ADDR, test_pwd, HAM_PWD_LEN);
    eeprom_write_byte_array(HAM_NOT_SENT_MSG_DELAY_ADDR,
                            (uint8_t *)&not_sent_test_delay, sizeof(uint32_t));
    eeprom_write_byte_array(HAM_SENT_MSG_DELAY_ADDR,
                            (uint8_t *)&sent_test_delay, sizeof(uint32_t));

    /* Run the function to be tested. */
    ham_update_data_from_eeprom(ham_pckt_id_cache, ham_pckt_timestamp_cache,
                                &ham_pckt_count, admin_pwd, &msg_delay);

    /* Check the message count. */
    TEST_ASSERT_EQUAL_UINT8(1, ham_pckt_count);

    /* Check the tag, timestamp, sender and recipient callsign loaded in the cache from the ham_update_data_from_eeprom function. */
    TEST_ASSERT_EQUAL_UINT32(ham_user_pckt->timestamp, ham_pckt_timestamp_cache[0]);
    TEST_ASSERT_EQUAL_UINT8(ham_user_pckt->tag, ham_pckt_id_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ham_user_pckt->data.recipient_callsign,
                                  &ham_pckt_id_cache[0][1], HAM_CALL_SIGN_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ham_user_pckt->data.sender_callsign,
                                  &ham_pckt_id_cache[0][7], HAM_CALL_SIGN_LEN);

    /* Check the password and delays loaded from the ham_update_data_from_eeprom function. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(admin_pwd, test_pwd, HAM_PWD_LEN);
    TEST_ASSERT_EQUAL_UINT8(msg_delay.sent_msg, sent_test_delay);
    TEST_ASSERT_EQUAL_UINT8(msg_delay.not_sent_msg, not_sent_test_delay);

    /* Delete the saved test message. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, (uint8_t *)&ham_pckt_eeprom,
                            sizeof(ham_user_packet_t));
}

void test_ham_check_saved_msg_states(void) {
    /* Creat empty user packet for clearing the eeprom. */
    ham_user_packet_t ham_pckt_eeprom = {0};
    /* Initialize the delays time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of messages statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;

    /* Store a test packet in the eeprom, the default tag is MSG_NOT_SENT. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, (uint8_t *)ham_user_pckt,
                            sizeof(ham_user_packet_t));

    /* Store a second test packet in the eeprom, with the MSG_SENT_TAG tag. */
    ham_user_pckt->tag = HAM_MSG_SENT_TAG;
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR + 1, (uint8_t *)ham_user_pckt,
                            sizeof(ham_user_packet_t));

    /* Get the needed datas from the eeprom. */
    ham_update_data_from_eeprom(ham_pckt_id_cache, ham_pckt_timestamp_cache,
                                &ham_pckt_count, admin_pwd, &msg_delay);

    /* Increase the timestamp by the value SENT_MSG_DELAY. */
    params.ttc_handle->timestamp = params.ttc_handle->timestamp + msg_delay.sent_msg;

    /* Run the function and check the tag of each packet. */
    ham_check_saved_msg_states(params.ttc_handle, ham_pckt_id_cache,
                               ham_pckt_timestamp_cache, &msg_delay, &ham_pckt_count);
    TEST_ASSERT_EQUAL_UINT8(HAM_MSG_NOT_SENT_TAG, ham_pckt_id_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8(HAM_MSG_ERASABLE_TAG, ham_pckt_id_cache[1][0]);

    /* Decrease the timestamp by HAM_SENT_MSG_DELAY for setting it to his initial value and increase by the value NOT_SENT_MSG_DELAY. */
    params.ttc_handle->timestamp =
        params.ttc_handle->timestamp - msg_delay.sent_msg + msg_delay.not_sent_msg;

    /* Run the function and check the tag of each packet. */
    ham_check_saved_msg_states(params.ttc_handle, ham_pckt_id_cache,
                               ham_pckt_timestamp_cache, &msg_delay, &ham_pckt_count);
    TEST_ASSERT_EQUAL_UINT8(HAM_MSG_ERASABLE_TAG, ham_pckt_id_cache[0][0]);
    TEST_ASSERT_EQUAL_UINT8(HAM_MSG_ERASABLE_TAG, ham_pckt_id_cache[1][0]);

    /* Delete the saved test message. */
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR, (uint8_t *)&ham_pckt_eeprom,
                            sizeof(ham_user_packet_t));
    eeprom_write_byte_array(HAM_MSG_EEPROM_ADDR + 1, (uint8_t *)&ham_pckt_eeprom,
                            sizeof(ham_user_packet_t));
}

void test_ham_handle_send_msg_cmd(void) {
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of packets statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;
    /* Packet for holding the datas read from eeprom. */
    ham_user_packet_t *ham_pckt_eeprom = NULL;
    ham_pckt_eeprom = (ham_user_packet_t *)malloc(sizeof(ham_user_packet_t));

    /* Set the command type of the packet to send. */
    ham_user_pckt->data.command = 's';

    /* Run the function to be tested. */
    ham_handle_send_msg_cmd(&params, &(rx_pckt->id), ham_user_pckt, ham_pckt_id_cache,
                            ham_pckt_timestamp_cache, &ham_pckt_count, debug);

    /* Dequeue ack/nack packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");

    /* check the ack type code and message code. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], RADIO_ACK_CODE_ACK);
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_MSG_STORED);

    /* Read the processed packet from the eeprom and check if it is correct. */
    eeprom_read_byte_array(HAM_MSG_EEPROM_ADDR, (uint8_t *)ham_pckt_eeprom,
                           sizeof(ham_user_packet_t));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ham_user_pckt, ham_pckt_eeprom,
                                  strlen((char *)ham_user_pckt));

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
    csp_buffer_free(pckt_sent_from_ham);
}

void test_ham_handle_ask_msg_cmd(void) {
    /* Creat a packet for the command ask message. */
    ham_user_packet_t *ham_pckt_ask_cmd = NULL;
    ham_pckt_ask_cmd = (ham_user_packet_t *)pvPortMalloc(sizeof(ham_user_packet_t));
    fill_generic_ham_user_pckt(ham_pckt_ask_cmd);
    create_ham_ask_msg_cmd(ham_pckt_ask_cmd);

    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of packets statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;

    /* Set the command type of the packet to send. */
    ham_user_pckt->data.command = 's';
    ham_handle_send_msg_cmd(&params, &(rx_pckt->id), ham_user_pckt, ham_pckt_id_cache,
                            ham_pckt_timestamp_cache, &ham_pckt_count, debug);

    /* Dequeue ack/nack packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");

    /* check the ack type code and message code. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], RADIO_ACK_CODE_ACK);
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_MSG_STORED);

    /* Run the function. */
    ham_handle_ask_msg_cmd(&params, &(rx_pckt->id), ham_pckt_ask_cmd,
                           ham_pckt_id_cache, ham_pckt_timestamp_cache, debug);

    /* Dequeue packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");

    /* Decrypt the data part of the packe without including the crc, tag and timestamp. */
    ham_decrypt_pckt_data(pckt_sent_from_ham->data, pckt_sent_from_ham->length,
                          HAM_CRC_LEN + HAM_TAG_LEN + HAM_TIMESTAMP_LEN);

    /* Check if the data part is correct. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pckt_sent_from_ham->data, ham_user_pckt,
                                  strlen((char *)ham_user_pckt));

    /* Free the buffer. */
    csp_buffer_free(rx_pckt);
    csp_buffer_free(pckt_sent_from_ham);
}

void test_ham_handle_get_cache_cmd(void) {
    /* Initialize the delay time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of packets statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;

    /* Get the needed datas from the eeprom. */
    ham_update_data_from_eeprom(ham_pckt_id_cache, ham_pckt_timestamp_cache,
                                &ham_pckt_count, admin_pwd, &msg_delay);

    /* Run the function to be tested. */
    ham_handle_get_cache_cmd(params.radio_tx_queue, &(rx_pckt->id), ham_pckt_id_cache,
                             ham_pckt_timestamp_cache, ham_pckt_count, debug);

    /* Dequeue packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");

    /* Check the number of cache msg created who is in the first byte of the data part. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], 1);

    /* Check the tag and callsigns. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(&pckt_sent_from_ham->data[1],
                                  &ham_pckt_id_cache[0][0],
                                  2 * HAM_CALL_SIGN_LEN + HAM_TAG_LEN);
    /* Check the timestamp. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY(&pckt_sent_from_ham->data[14],
                                  &ham_pckt_timestamp_cache[0], HAM_TIMESTAMP_LEN);
}

void test_ham_handle_admin_cmd(void) {
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    uint8_t ham_pckt_count = 0;
    /* Initialize the delay time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};

    /* Call the ham handle admin command with a wrong password. */
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);
    /* Dequeue ack/nack packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");

    /* check the nack type code and message code. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], RADIO_ACK_CODE_NACK);
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_PWD);
    /* Call the ham handle admin command with a correct password but wrong command. */
    fill_generic_ham_admin_pckt((ham_admin_packet_t *)rx_pckt->data);
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);

    /* Dequeue ack/nack packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the nack type code and message code. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], RADIO_ACK_CODE_NACK);
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the delete all message command is directed to his function. */
    rx_pckt->data[3] = HAM_DEL_ALL_MSG_CMD;
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the update not sent message delay command is directed to his function. */
    rx_pckt->data[3] = HAM_UPD_NOT_SENT_MSG_DELAY_CMD;
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the update sent message delay command is directed to his function. */
    rx_pckt->data[3] = HAM_UPD_SENT_MSG_DELAY_CMD;
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the update password command is directed to his function. */
    rx_pckt->data[3] = HAM_UPD_PWD_CMD;
    ham_handle_admin_cmd(&params, rx_pckt, ham_pckt_id_cache, &ham_pckt_count,
                         &msg_delay, admin_pwd, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);
}

void test_ham_handle_user_cmd(void) {
    /* Array for storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    /* Array for storing the timestamp of packets statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    uint8_t ham_pckt_count = 0;

    /* Call the ham handle user command with a wrong command. */
    ham_handle_user_cmd(&params, rx_pckt, ham_pckt_id_cache,
                        ham_pckt_timestamp_cache, &ham_pckt_count, debug);
    /* Dequeue ack/nack packet from the radio tx queue. */
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* check the nack type code and message code. */
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[0], RADIO_ACK_CODE_NACK);
    TEST_ASSERT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the send message command is directed to his function. */
    rx_pckt->data[3] = HAM_SEND_MSG_CMD;
    ham_handle_user_cmd(&params, rx_pckt, ham_pckt_id_cache,
                        ham_pckt_timestamp_cache, &ham_pckt_count, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the ask message command is directed to his function. */
    rx_pckt->data[3] = HAM_ASK_MSG_CMD;
    ham_handle_user_cmd(&params, rx_pckt, ham_pckt_id_cache,
                        ham_pckt_timestamp_cache, &ham_pckt_count, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);

    /* Test if the get cache command is directed to his function. */
    rx_pckt->data[3] = HAM_GET_CACHE_CMD;
    ham_handle_user_cmd(&params, rx_pckt, ham_pckt_id_cache,
                        ham_pckt_timestamp_cache, &ham_pckt_count, debug);
    rv = xQueueReceive(params.radio_tx_queue, &pckt_sent_from_ham, 0);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(
        pdFALSE, rv, "Could not dequeue packet from radio tx queue");
    /* Check the ack/nack message code. */
    TEST_ASSERT_NOT_EQUAL_UINT8(pckt_sent_from_ham->data[1], HAM_INV_CMD);
}

void test_string_to_int(void){
    /* Creat a valid string that can be converted in to integer. */
    uint8_t valid_test_str[3]={'1','2','3'};
    /* Creat a invalid string that cant be converted in to integer. */
    uint8_t invalid_test_str[3]={'a','2','3'};
    uint32_t res;
    uint8_t rv;

    /* Try to convert the created strings and check the return value. */
    rv=string_to_int(&valid_test_str,3,&res);
    TEST_ASSERT_EQUAL_UINT8(0, rv);
    rv=string_to_int(&invalid_test_str,3,&res);
    TEST_ASSERT_EQUAL_UINT8(1, rv);
}

void test_ham_handle_upd_not_sent_msg_delay_cmd(void) {
    /* Creat a variable to hold the delay time read from eeprom. */
    uint32_t eeprom_delay = 0;
    /* Initialize the delay time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};
    /* Initialize a different delay value. */
    uint8_t test_not_sent_delay[HAM_NOT_SENT_MSG_MAX_DELAY_LEN] = {'4',  '3',  '2',
                                                          '2', '1', '\0'};

    /* Fill the admin packet data part with the test not sent delay value. */
    memcpy(ham_admin_pckt->data, test_not_sent_delay, HAM_NOT_SENT_MSG_MAX_DELAY_LEN);

    /* Run the function to be tested. */
    ham_handle_upd_not_sent_msg_delay_cmd(params.radio_tx_queue, &(rx_pckt->id), ham_admin_pckt,
                                          &(msg_delay.not_sent_msg), debug);

    /* Cheack if the delay i changed correctly. */
    TEST_ASSERT_EQUAL_UINT32(msg_delay.not_sent_msg, atoi((char *)test_not_sent_delay));

    /* Read and check the eerpom if the delay time is saved successfully. */
    eeprom_read_byte_array(HAM_NOT_SENT_MSG_DELAY_ADDR,
                           (uint8_t *)&eeprom_delay, HAM_NOT_SENT_MSG_MAX_DELAY_LEN);
    TEST_ASSERT_EQUAL_UINT32(msg_delay.not_sent_msg, eeprom_delay);
}

void test_ham_handle_upd_sent_msg_delay_cmd(void) {
    /* Creat a variable to hold the delay time read from eeprom. */
    uint32_t eeprom_delay = 0;
    /* Initialize the delay time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};
    /* Initialize a different delay value. */
    uint8_t test_sent_delay[HAM_SENT_MSG_MAX_DELAY_LEN] = {'2',  '0',  '\0'};

    /* Fill the admin packet data part with the test not sent delay value. */
    memcpy(ham_admin_pckt->data, test_sent_delay, HAM_SENT_MSG_MAX_DELAY_LEN);

    /* Run the function to be tested. */
    ham_handle_upd_sent_msg_delay_cmd(params.radio_tx_queue, &(rx_pckt->id),
                                      ham_admin_pckt, &(msg_delay.sent_msg), debug);

    /* Cheack if the delay is changed correctly. */
    TEST_ASSERT_EQUAL_UINT32(msg_delay.sent_msg, atoi((char *)test_sent_delay));

    /* Read and check the eeprom if the delay time is saved successfully. */
    eeprom_read_byte_array(HAM_SENT_MSG_DELAY_ADDR, (uint8_t *)&eeprom_delay,
                           sizeof(uint32_t));
    TEST_ASSERT_EQUAL_UINT32(msg_delay.sent_msg, eeprom_delay);
}

void test_ham_handle_upd_pwd_cmd(void) {
    /* Creat a different password from the initial password for saving it in the eeprom (the same password is included twice for security). */
    uint8_t test_pwd[HAM_PWD_LEN * 2] = {'8', '7', '3', '4', '5', '4',
                                         '8', '7', '3', '4', '5', '4'};
    /* Variable which will contain the password read from the eeprom.  */
    uint8_t eeprom_pwd[HAM_PWD_LEN];
    /* Fill the data part of the packet with the password (the same password is included twice for security). */
    memcpy(ham_admin_pckt->data, test_pwd, HAM_PWD_LEN * 2);

    /* Run the function to be tested. */
    ham_handle_upd_pwd_cmd(params.radio_tx_queue, &(rx_pckt->id),
                           ham_admin_pckt, admin_pwd, debug);

    /* Check if the password is changed and saved in the eeprom successfully. */
    TEST_ASSERT_EQUAL_CHAR_ARRAY(test_pwd, admin_pwd, HAM_PWD_LEN);
    eeprom_read_byte_array(HAM_PWD_ADDR, eeprom_pwd, HAM_PWD_LEN);
    TEST_ASSERT_EQUAL_CHAR_ARRAY(eeprom_pwd, admin_pwd, HAM_PWD_LEN);
}

void test_ham_handle_del_all_msg_cmd(void) {
    /* For storing the timestamp of packets statically. */
    uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR] = {0};
    /* For storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN] = {0};
    uint8_t ham_pckt_cnt = 0;
    /* Initialize the delay time used for deleting the messages according the tag. */
    ham_msg_delay_t msg_delay = {HAM_SENT_MSG_DELAY, HAM_NOT_SENT_MSG_DELAY};

    /* Get the needed datas from the eeprom. */
    ham_update_data_from_eeprom(ham_pckt_id_cache, ham_pckt_timestamp_cache,
                                &ham_pckt_cnt, admin_pwd, &msg_delay);

    /* Run the function to be tested. */
    ham_handle_del_all_msg_cmd(params.radio_tx_queue, &(rx_pckt->id),
                               ham_pckt_id_cache, &ham_pckt_cnt, debug);

    /* Get the needed datas from the eeprom to check if all the messages are deleted. */
    ham_update_data_from_eeprom(ham_pckt_id_cache, ham_pckt_timestamp_cache,
                                &ham_pckt_cnt, admin_pwd, &msg_delay);

    /* Check the packet count. */
    TEST_ASSERT_EQUAL_CHAR(ham_pckt_cnt, 0);
}

void fill_generic_csp_pckt_header(csp_packet_t *csp_pckt) {
    /* Fill the csp packet header with id appropriate to the HAM radio system task. */
    csp_pckt->id.flags = 0x00;
    csp_pckt->id.sport = 0x01;
    csp_pckt->id.dport = 0x01;
    csp_pckt->id.src = 0x1D;
    csp_pckt->id.dst = 0x09;
    csp_pckt->id.pri = 0x02;
}

void fill_generic_ham_user_pckt(ham_user_packet_t *ham_user_pckt) {
    /* Fill ham radio user packet with a tag,timestamp,crc,command type,command,sender callsign,recipient callsign and message to send. */
    uint8_t ham_test_pckt[26] = {1,   '2', '2', '2', '2', '3', '3', 'u', '4',
                                 '5', '5', '5', '5', '5', '5', '6', '6', '6',
                                 '6', '6', '6', '7', '7', '7', '7', '7'};

    /* Copy the ham test packet in to the ham user packet. */
    memcpy(ham_user_pckt, ham_test_pckt, 26);

    /* Change the timestamp of the packets with the curren timestamp. */
    ham_user_pckt->timestamp = params.ttc_handle->timestamp;
}

void create_ham_ask_msg_cmd(ham_user_packet_t *ham_user_pckt) {
    /* Change sender callsign with the recipient callsign. */
    memcpy(ham_user_pckt->data.sender_callsign,
           ham_user_pckt->data.recipient_callsign, HAM_CALL_SIGN_LEN);

    /* Change the command type to user cmd. */
    ham_user_pckt->data.command_type = HAM_USER_CMD;

    /* Change the command to ask message. */
    ham_user_pckt->data.command = HAM_ASK_MSG_CMD;
}

void fill_generic_ham_admin_pckt(ham_admin_packet_t *ham_admin_pckt) {
    /* Fill ham radio user packet with a tag,timestamp,crc,command type,command,sender callsign,recipient callsign and message to send. */
    uint8_t ham_test_pckt[16] = {'c', 'c', 'a', 'm', 'p', 'p', 'p', 'p',
                                 'p', 'p', 'd', 'd', 'd', 'd', 'd', 'd'};

    /* Copy the ham test packet in to the ham user packet. */
    memcpy(ham_admin_pckt, ham_test_pckt, 16);
    memcpy(ham_admin_pckt->pwd, admin_pwd, HAM_PWD_LEN);
}
