/** @file hamradio_messaging_system_task.c
 *  @brief HAMRadio Messaging System Implementation.
 */

#include "kernel/FreeRTOS.h"
#include "kernel/os_queue.h"
#include "kernel/os_task.h"

#include "app/rob3u/ham_messaging_sys_task.h"

#include "lib/csp_handler/libcsp_formatter.h"
#include "lib/libcsp/include/csp/csp_types.h"
#include "lib/libsrdb/R3A_Csp_Header.h"
#include "app/rob3u/queues.h"
#include "hal/eeprom.h"
#include <stdlib.h>

#include "app/rob3u/ttc_conf.h"

#include "hal/debug.h"

/* Under FREERTOS use thread safe memory allocation. */
#ifdef FREERTOS
#include "kernel/FreeRTOS.h"
#define malloc(size) pvPortMalloc(size)
#define free(ptr) vPortFree(ptr)
#else
#include <stdlib.h>
#endif

void ham_messaging_sys_task(void *task_params) {

    TickType_t last_wake_time;
    
    ham_messaging_sys_task_params_t *params =(ham_messaging_sys_task_params_t *)task_params;
    static BaseType_t ham_pkt_rx_queue_count = 0;
    static const uint8_t debug = 1;
    static csp_packet_t *rx_pkt = NULL;
    static ham_packet_t *ham_pkt = NULL;
    static csp_packet_t *ack_nack_csp_pkt = NULL;
    static uint8_t rv;
    uint8_t ham_pkt_count = 0;
    
    /* For storing the tag, the recipient and sender callsign statically. */
    uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN]={0}; 
    /* For storing the timestamp of packets statically. */
    uint32_t ham_pkt_timestamp_cache[HAM_MAX_MSG_NUM]={0};

    eeprom_init();
    update_cache_from_eeprom(ham_pkt_id_cache,ham_pkt_timestamp_cache,&ham_pkt_count);

    params->ttc_handle->timestamp=1618581400;
    srand(params->ttc_handle->timestamp);
    last_wake_time = xTaskGetTickCount();
    while(1) {
        /* Sleep for the remaining of the task period. */
        vTaskDelayUntil(&last_wake_time, pdMS_TO_TICKS(params->task_period));
        vTaskDelay(pdMS_TO_TICKS(5000));
        params->ttc_handle->timestamp=params->ttc_handle->timestamp+5;
        debug_printf_def_trace(debug,"HAM MSG SYS\n\r");

        check_saved_msg_states(params,ham_pkt_id_cache,ham_pkt_timestamp_cache,&ham_pkt_count);
       
        /*Check if there is ham radio packet in the queue */
        ham_pkt_rx_queue_count = uxQueueMessagesWaiting(params->ham_packet_rx_queue);

        if(ham_pkt_rx_queue_count == 0) continue;
        while (ham_pkt_rx_queue_count>0)
        {
            rv = xQueueReceive(params->ham_packet_rx_queue, &rx_pkt, 0);
            if(rv == pdFALSE) {
                debug_printf_def_trace(debug,
                                    "Could not dequeue packet from "
                                    "ham_packet_rx_queue.\n\r");
                continue;
            }
            debug_printf_def_trace(debug, "Dequeued packet.\n\r");
            ham_pkt_rx_queue_count--;

            rv = decrypt_pkt_data(rx_pkt->data, rx_pkt->length,HAM_CRC_LEN);
            if(rv) {
                /* Invalid Ham packet ,delete packet! Creat NACK and advance the loop. */
                debug_printf_def_trace(debug, "Packet invalid.\n\r");
                ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_INV_PKT);
                push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                continue;
            }
            debug_printf_def_trace(debug, "Packet valid.\n\r");

            ham_pkt = (ham_packet_t *)malloc(sizeof(ham_packet_t));
            memcpy(&ham_pkt->data, rx_pkt->data, sizeof(ham_packet_data_t));

            /* Check the command type. */
            switch (ham_pkt->data.command)
            {
            case HAM_SEND_MSG_CMD:
                handle_send_msg_cmd(params,rx_pkt,ham_pkt,ham_pkt_id_cache,ham_pkt_timestamp_cache,&ham_pkt_count,debug);
                break;
            case HAM_ASK_MSG_CMD:
                handle_ask_msg_cmd(params,rx_pkt,ham_pkt,ham_pkt_id_cache,ham_pkt_timestamp_cache,debug);
                break;
            case HAM_GET_CACHE_CMD:
                handle_get_cache_cmd(params,rx_pkt,ham_pkt_id_cache,ham_pkt_timestamp_cache,ham_pkt_count,debug);
                break;
            default:
                /* Invalid command ! Creat and send NACK. */
                ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_INV_CMD);
                push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
            }
            // rx_pkt buffer free
        }
    }
}

void build_ack_nack_csp_pkt(csp_packet_t *ack_nack_csp_pkt,const csp_packet_t *src_pkt,const uint8_t type_code,const uint8_t msg_code) {
    
    ack_nack_csp_pkt->id.flags = 0x00;/* CSP_FCRC32; */
    ack_nack_csp_pkt->id.sport = src_pkt->id.dport;
    ack_nack_csp_pkt->id.dport = src_pkt->id.sport;
    ack_nack_csp_pkt->id.dst = src_pkt->id.src;
    ack_nack_csp_pkt->id.src = CSP_ADD_HAMRADIO_TASK;
    ack_nack_csp_pkt->id.pri = 0;

    ack_nack_csp_pkt->length = HAM_ACK_NACK_PKT_LEN;
    ack_nack_csp_pkt->data[0] = type_code; 
    ack_nack_csp_pkt->data[1] = msg_code;
    // TODO : add delay before sending ? 
}

void build_ham_csp_pkt(csp_packet_t *ham_csp_pkt, const ham_packet_t *data_to_send, const csp_packet_t *src_pkt) {
    
    ham_csp_pkt->id.flags = 0x00; /* CSP_FCRC32;*/
    ham_csp_pkt->id.sport = src_pkt->id.dport;
    ham_csp_pkt->id.dport = src_pkt->id.sport;
    ham_csp_pkt->id.dst = src_pkt->id.src;
    ham_csp_pkt->id.src = CSP_ADD_HAMRADIO_TASK;
    ham_csp_pkt->id.pri = 0;
    ham_csp_pkt->length=HAM_MAX_ID_LEN+strlen(data_to_send->data.message);

    memcpy(ham_csp_pkt->data,data_to_send,sizeof(ham_packet_t));
    encrypt_pkt_data(ham_csp_pkt->data,ham_csp_pkt->length,(HAM_TAG_LEN+HAM_CRC_LEN+HAM_TIMESTAMP_LEN));
    
    // TODO : add delay before sending ? 
}

void build_cache_csp_packet(csp_packet_t *cache_csp_pkt,const csp_packet_t *src_pkt,const uint8_t *data_to_send,const uint8_t data_len,const uint8_t cache_msg_num){

    cache_csp_pkt->id.flags = CSP_FCRC32;
    cache_csp_pkt->id.sport = src_pkt->id.dport;
    cache_csp_pkt->id.dport = src_pkt->id.sport;
    cache_csp_pkt->id.dst = src_pkt->id.src;
    cache_csp_pkt->id.src = CSP_ADD_HAMRADIO_TASK;
    cache_csp_pkt->id.pri = 0;
    cache_csp_pkt->length=data_len+sizeof(cache_msg_num);

    cache_csp_pkt->data[0]=cache_msg_num;
    memcpy(&cache_csp_pkt->data[1],data_to_send,data_len);
}

uint8_t push_pkt_to_radio_tx_queue(const ham_messaging_sys_task_params_t *params,const csp_packet_t *pkt_to_push) {
    
    const uint8_t rv = xQueueSend(params->radio_tx_queue, &pkt_to_push, 0); // TODO : add wait 0 or 10 ?
    /* If queue is full, send error code to HK task */
    if(rv == errQUEUE_FULL) {
        register_event_to_queue(TTC_EVENT_RADIO_TX_QUEUE_FULL, 0);
        return 1;
    }
    return 0;

}

uint8_t decrypt_pkt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start) {
    
    const uint8_t key[]={};

    const uint8_t num_of_element_key[]={};

    /* Decrypt the giving data array without including the crc. */
    uint16_t calculated_crc=0;
    uint8_t count=index_to_start;

        for (uint8_t i = index_to_start; i <data_len; i++)
        {
            for (uint8_t j = 0; j <(sizeof(key) / sizeof(key[0])); j++)
            {
                if (key[j]==data[i])
                {   
                    data[count]=num_of_element_key[j];
                    calculated_crc=j+calculated_crc;
                    count++;
                    break;
                }
            }
        }
        /* checking the crc. */
        uint16_t rx_data_crc=data[0]+(data[1]<<8);
        if(calculated_crc == rx_data_crc)
            return 0;
        else
            return 1;
}

void encrypt_pkt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start) {
    
    const uint8_t key[]={};

    const uint8_t num_of_element_key[]={};
    /* Encrypt the given data without including the crc, timestamp and tag. */
    uint8_t data_key_index;
    uint8_t key_data=0;
    for (uint8_t i = index_to_start; i < data_len; i++)
    {
        uint8_t rand_num_limit=0;
        for (uint8_t j = 0; j < sizeof(num_of_element_key) / sizeof(num_of_element_key[0]); j++)
        {
            if(num_of_element_key[j]==data[i]){
                if (rand_num_limit==0)
                {
                    data_key_index=j;
                }
                rand_num_limit++; 
            }
        }
        key_data=data_key_index+(rand()%rand_num_limit);
        data[i]=key[key_data];
    }
}

void update_cache_from_eeprom(uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count){
    
    static ham_packet_t *ham_pkt_eeprom = NULL;
    ham_pkt_eeprom = (ham_packet_t *)malloc(sizeof(ham_packet_t));

    for (uint8_t i = 0; i < HAM_MAX_MSG_NUM; i++)
    {
        eeprom_read_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
        if (ham_pkt_eeprom->pkt_tag==HAM_MSG_SENT_TAG||ham_pkt_eeprom->pkt_tag==HAM_MSG_NOT_SENT_TAG)
        {
            ham_pkt_timestamp_cache[i]=ham_pkt_eeprom->timestamp;
            ham_pkt_id_cache[i][0]=ham_pkt_eeprom->pkt_tag;
            memcpy(&ham_pkt_id_cache[i][1],ham_pkt_eeprom->data.recipient_callsign,HAM_CALL_SIGN_LEN);
            memcpy(&ham_pkt_id_cache[i][7],ham_pkt_eeprom->data.sender_callsign,HAM_CALL_SIGN_LEN); 
            (*ham_pkt_count)++;  
        }
    }
    free(ham_pkt_eeprom);
}

void check_saved_msg_states(const ham_messaging_sys_task_params_t *params,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count){
    
    static ham_packet_t *ham_pkt_eeprom = NULL;
    ham_pkt_eeprom = (ham_packet_t *)malloc(sizeof(ham_packet_t));
    /* Check the timestamp of the packets and change the tag according to that. */
        for (uint8_t i = 0; i < HAM_MAX_MSG_NUM; i++)
        {
            if (ham_pkt_id_cache[i][0]==HAM_MSG_SENT_TAG)
            {
                if ((params->ttc_handle->timestamp-ham_pkt_timestamp_cache[i])>=HAM_SENT_MSG_DELAY)
                {
                    ham_pkt_id_cache[i][0]=HAM_MSG_ERASABLE_TAG;
                    eeprom_read_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    ham_pkt_eeprom->pkt_tag=HAM_MSG_ERASABLE_TAG;
                    eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    /* Decrease the stored packet number. */
                    (*ham_pkt_count)--;
                }
            }
            else if (ham_pkt_id_cache[i][0]==HAM_MSG_NOT_SENT_TAG)
            {
                if ((params->ttc_handle->timestamp-ham_pkt_timestamp_cache[i])>=HAM_NOT_SENT_MSG_DELAY)
                {
                    ham_pkt_id_cache[i][0]=HAM_MSG_ERASABLE_TAG;
                    eeprom_read_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    ham_pkt_eeprom->pkt_tag=HAM_MSG_ERASABLE_TAG;
                    eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    /* Decrease the stored packet number. */
                    (*ham_pkt_count)--;
                }
            }
        }
        free(ham_pkt_eeprom);
}

void handle_send_msg_cmd(const ham_messaging_sys_task_params_t *params,csp_packet_t *rx_pkt,ham_packet_t *ham_pkt,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],uint8_t *ham_pkt_count,const uint8_t debug){
                
                static uint8_t rv=0;
                static uint8_t callsign_to_check[HAM_CALL_SIGN_LEN]={0};
                static csp_packet_t *ack_nack_csp_pkt = NULL;
                
                if((*ham_pkt_count) >= HAM_MAX_MSG_NUM) 
                {
                    /* The maximum number of messages has been reached ! Creat NACK and advance the loop. */
                    ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_MAX_MSG_NUM_REACHED);
                    push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                    return;
                }

                uint8_t allowed_msg_num_reached=0;
                if ((*ham_pkt_count)>0)
                {   /* Checking how many message has stored the person. */
                    uint8_t allowed_msg_count=0;
                    for (uint8_t i = 0; i < HAM_MAX_MSG_NUM; i++)
                    {   
                        if (ham_pkt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG) continue;
                        memcpy(&callsign_to_check,&ham_pkt_id_cache[i][7],HAM_CALL_SIGN_LEN);
                        rv=strncmp(callsign_to_check,ham_pkt->data.sender_callsign,HAM_CALL_SIGN_LEN);
                        if (rv==0)
                        {
                            allowed_msg_count++;
                            if (allowed_msg_count==HAM_ALLOWED_MSG_NUM)
                            {   
                                allowed_msg_num_reached=1;
                                break;
                            }
                        }
                    }
                }

                if (allowed_msg_num_reached==1)
                {   /* Creat ACK and advance the loop if the person has reached the allowed storable message number. */
                    debug_printf_def_trace(debug, "Allowed storable message number reached.\n\r");
                    ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_ALLOWED_MSG_NUM_REACHED);
                    push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                    return;
                }

                uint8_t msg_len = strlen(ham_pkt->data.message); 
                // rx_pkt->length-MAX_ID_LENGTH = message length
                if (msg_len>HAM_MAX_MSG_LEN)
                {
                    /* The maximum length of the messages exceeded ! Creat NACK and advance the loop. */
                    ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_MAX_MSG_LEN_EXCEED);
                    push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                    return;
                }
               

                for (uint8_t i = 0; i < HAM_MAX_MSG_NUM; i++)
                {
                    if (ham_pkt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG)
                    {   
                        /* Set the tag to message not sent. */
                        ham_pkt->pkt_tag = HAM_MSG_NOT_SENT_TAG;
                        
                        /* Add the time stamp. */
                        ham_pkt->timestamp=params->ttc_handle->timestamp;

                        /* Store the call sing,time stamp and tag in the cache. */
                        ham_pkt_timestamp_cache[i]=params->ttc_handle->timestamp;
                        ham_pkt_id_cache[i][0]=ham_pkt->pkt_tag;
                        memcpy(&ham_pkt_id_cache[i][1],ham_pkt->data.recipient_callsign,HAM_CALL_SIGN_LEN);
                        memcpy(&ham_pkt_id_cache[i][7],ham_pkt->data.sender_callsign,HAM_CALL_SIGN_LEN);

                        /* Store the message in the eeprom ! Creat ACK and advance the loop. */
                        eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, ham_pkt, sizeof(ham_packet_t));
                        ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                        build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_ACK,HAM_MSG_STORED);
                        push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);

                        /* Increase the packet number. */
                        (*ham_pkt_count)++;
                        debug_printf_def_trace(debug, "Message stored.\n\r");
                        break;
                    }
                    
                }
}

void handle_ask_msg_cmd(const ham_messaging_sys_task_params_t *params,csp_packet_t *rx_pkt,ham_packet_t *ham_pkt,uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],uint32_t ham_pkt_timestamp_cache[],const uint8_t debug){

                uint8_t search_state;
                uint32_t prev_timestamp;
                uint8_t msg_search_init=0;
                uint8_t msg_to_send_addr;
                static csp_packet_t *ack_nack_csp_pkt = NULL;
                static csp_packet_t *ham_csp_pkt = NULL;
                static ham_packet_t *ham_pkt_eeprom = NULL;
                ham_pkt_eeprom = (ham_packet_t *)malloc(sizeof(ham_packet_t));
                static uint8_t callsign_to_check[HAM_CALL_SIGN_LEN]={0};

                for (uint8_t i = 0; i < HAM_MAX_MSG_NUM; i++)
                { 
                    /* The packet tag is erasable so dont send it, advance the loop. */
                    if (ham_pkt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG)
                    {
                        continue;
                    }

                    /* Search for the first message sent for the given person */
                    memcpy(&callsign_to_check,&ham_pkt_id_cache[i][1],HAM_CALL_SIGN_LEN);
                    search_state=strncmp(callsign_to_check,ham_pkt->data.sender_callsign,HAM_CALL_SIGN_LEN);
                    if (search_state==0)
                    {
                        
                        if (prev_timestamp>ham_pkt_timestamp_cache[i]||msg_search_init==0)
                        {
                            prev_timestamp=ham_pkt_timestamp_cache[i];
                            msg_to_send_addr=i;
                            msg_search_init=1;
                        }
                        
                    }
                }

                if (search_state==0)
                {
                    debug_printf_def_trace(debug, "Message Found.\n\r");
                    /* Message found send it. */
                    eeprom_read_byte_array(msg_to_send_addr+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    ham_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ham_csp_pkt(ham_csp_pkt,ham_pkt_eeprom,rx_pkt);
                    push_pkt_to_radio_tx_queue(params,ham_csp_pkt);

                    /* Change the tag of the packet to sent and re-store it. */
                    ham_pkt_eeprom->pkt_tag = HAM_MSG_SENT_TAG;
                    /* Update the time stamp of the packet. */
                    //ham_pkt->timestamp=params->ttc_handle->timestamp;
                    ham_pkt_id_cache[msg_to_send_addr][0]=ham_pkt_eeprom->pkt_tag;
                    ham_pkt_timestamp_cache[msg_to_send_addr]=params->ttc_handle->timestamp;
                    eeprom_write_byte_array(msg_to_send_addr+HAM_MSG_EEPROM_ADDR, ham_pkt_eeprom, sizeof(ham_packet_t));
                    debug_printf_def_trace(debug, "Message sent.\n\r");
                    free(ham_pkt_eeprom);
                    return;
                }
                
                if (search_state!=0)
                {
                    /* Message not found ? creat and send ACK. */
                    debug_printf_def_trace(debug, "No Message.\n\r");
                    ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_NO_MSG);
                    push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                }
                free(ham_pkt_eeprom);
}

void handle_get_cache_cmd(const ham_messaging_sys_task_params_t *params,const csp_packet_t *rx_pkt,const uint8_t ham_pkt_id_cache[HAM_MAX_MSG_NUM][(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN],const uint32_t ham_pkt_timestamp_cache[],const uint8_t ham_pkt_count,const uint8_t debug){
                
                static csp_packet_t *ack_nack_csp_pkt = NULL;
                if (ham_pkt_count==0)
                {
                    /* No cache data to send ? creat and send ACK. */
                    debug_printf_def_trace(debug, "No cache data.\n\r");
                    ack_nack_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_ack_nack_csp_pkt(ack_nack_csp_pkt,rx_pkt,RADIO_ACK_CODE_NACK,HAM_NO_CHACHE_DATA);
                    push_pkt_to_radio_tx_queue(params,ack_nack_csp_pkt);
                    return;
                }

                /* Sending all the data stored in the cache to the user. */
                debug_printf_def_trace(debug, "Sending cache data.\n\r");

                /* Calculate the number of csp packet needed to be created for sending all the data considering the maximum size of the data field of a CSP packet. */
                static csp_packet_t *cache_csp_pkt = NULL;
                uint8_t num_of_pkt_to_be_created=(ham_pkt_count-(ham_pkt_count%HAM_MAX_CACHE_MSG_NUM))/HAM_MAX_CACHE_MSG_NUM;
                uint8_t i=0;
                for (uint8_t j = 0; j <= num_of_pkt_to_be_created; j++)
                {
                    uint8_t cache_data_to_send[TTC_CSP_BUFFER_DATA_SIZE-TTC_CSP_CRC_FIELD_LEN]={0};
                    uint8_t cache_count=0;
                    for (i = i; i < HAM_MAX_MSG_NUM; i++)
                    {
                        if (cache_count==HAM_MAX_CACHE_MSG_NUM)
                        {
                            /* Check if the packet is full. */
                            break;
                        }
                        if (ham_pkt_id_cache[i][0]==HAM_MSG_SENT_TAG||ham_pkt_id_cache[i][0]==HAM_MSG_NOT_SENT_TAG)
                        {
                            /* Fill the data to send with just the cache data that has sent and not sent tag. */
                            memcpy(&cache_data_to_send[0+(HAM_CACHE_MSG_DATA_LEN*cache_count)],&ham_pkt_id_cache[i][0],(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN);
                            memcpy(&cache_data_to_send[(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN+(HAM_CACHE_MSG_DATA_LEN*cache_count)],&ham_pkt_timestamp_cache[i],HAM_TIMESTAMP_LEN);
                            cache_count++;
                        }
                    }

                    /* Creat and send packet. */
                    cache_csp_pkt = csp_buffer_get(csp_buffer_data_size());
                    build_cache_csp_packet(cache_csp_pkt,rx_pkt,cache_data_to_send,(HAM_CACHE_MSG_DATA_LEN*cache_count),cache_count);
                    push_pkt_to_radio_tx_queue(params,cache_csp_pkt);
                }
}
