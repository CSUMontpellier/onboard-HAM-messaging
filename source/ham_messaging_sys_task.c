/** @file ham_messaging_sys_task.c
 *  @brief HAMRadio Messaging System Implementation.
 */

#include "os/FreeRTOS.h"
#include "os/os_queue.h"
#include "os/os_task.h"

#include <app/rob3u/csum_packet_processing_task.h>
#include "app/rob3u/ham_messaging_sys_task.h"
#include "app/rob3u/ttc_conf.h"

#include "libs/csp_handler/libcsp_formatter.h"
#include "libs/libcsp/include/csp/csp_types.h"
#include "libs/libsrdb/libsrdb_config.h"
#include "app/rob3u/queues.h"
#include "hal/eeprom.h"
#include <stdlib.h>
#include <stdbool.h>
#include "hal/debug.h"

void ham_messaging_sys_task(void *task_params) {
    
    ham_msg_sys_task_params_t *params =(ham_msg_sys_task_params_t *)task_params;
    uint8_t ham_pckt_rx_queue_count = 0;
    const uint8_t debug = 1;
    static csp_packet_t *rx_pckt = NULL;
    static csp_packet_t *ack_nack_csp_pckt = NULL;
    uint8_t rv;
    uint8_t ham_pckt_count = 0;
    extern uint8_t admin_pwd[];

    /* Initialize the delay time before deleting the messages according the tag. */
    ham_msg_delay_t msg_delay={HAM_SENT_MSG_DELAY,HAM_NOT_SENT_MSG_DELAY};
    
    /* Array for storing the tag, the recipient and sender callsign statically. */
    static uint8_t ham_pckt_id_cache[HAM_MAX_MSG_NBR][HAM_ID_LEN]={0}; 
    /* Array for storing the timestamp of packets statically. */
    static uint32_t ham_pckt_timestamp_cache[HAM_MAX_MSG_NBR]={0};

    eeprom_init();
    ham_update_data_from_eeprom(ham_pckt_id_cache,ham_pckt_timestamp_cache,&ham_pckt_count,admin_pwd,&msg_delay);

    params->ttc_handle->timestamp=1618581400;
    srand(params->ttc_handle->timestamp);

    while(1) {
        /* Sleep for the remaining of the task period. */
        vTaskDelay(pdMS_TO_TICKS(params->task_period));
        vTaskDelay(pdMS_TO_TICKS(5000));
        params->ttc_handle->timestamp=params->ttc_handle->timestamp+5;
        debug_printf_def_trace(debug,"HAM MSG SYS\n\r");

        ham_check_saved_msg_states(params->ttc_handle,ham_pckt_id_cache,ham_pckt_timestamp_cache,&msg_delay,&ham_pckt_count);
       
        /* Check if there is ham radio packet in the queue. */
        ham_pckt_rx_queue_count = uxQueueMessagesWaiting(params->ham_packet_rx_queue);

        if(ham_pckt_rx_queue_count == 0) continue;
        while (ham_pckt_rx_queue_count>0)
        {   
            memset(&rx_pckt,0,csp_buffer_data_size());
            rv = xQueueReceive(params->ham_packet_rx_queue, &rx_pckt, 0);
            if(rv == pdFALSE) {
                debug_printf_def_trace(debug,
                                    "Could not dequeue packet from "
                                    "ham_packet_rx_queue.\n\r");
                continue;
            }
            debug_printf_def_trace(debug, "Dequeued packet.\n\r");
            ham_pckt_rx_queue_count--;

            rv = ham_decrypt_pckt_data(rx_pckt->data, rx_pckt->length,HAM_CRC_LEN);
            if(rv) {
                /* Invalid Ham packet ,delete packet! Creat NACK and advance the loop. */
                debug_printf_def_trace(debug, "HAM CRC invalid.\n\r");
                ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                if (ack_nack_csp_pckt==NULL){
                    csp_buffer_free(rx_pckt);
                    continue;
                }
                ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,&(rx_pckt->id),RADIO_ACK_CODE_NACK,HAM_INV_CRC);
                push_packet_to_radio_tx_queue(ack_nack_csp_pckt,params->radio_tx_queue);
                csp_buffer_free(rx_pckt);
                continue;
            }
            debug_printf_def_trace(debug, "Packet valid.\n\r");

            /* Get the command type. */
            uint8_t command_type=rx_pckt->data[HAM_PCKT_CMD_TYPE_INDEX];

            switch (command_type)
            {
                case HAM_USER_CMD:
                    ham_handle_user_cmd(params,rx_pckt,ham_pckt_id_cache,ham_pckt_timestamp_cache,&ham_pckt_count,debug);
                    break;
                case HAM_ADMIN_CMD:
                    ham_handle_admin_cmd(params,rx_pckt,ham_pckt_id_cache,&ham_pckt_count,&msg_delay,admin_pwd,debug);
                    break;
                default:
                    /* Invalid command type ! Creat and send NACK. */
                    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ack_nack_csp_pckt==NULL) break;
                    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,&(rx_pckt->id),RADIO_ACK_CODE_NACK,HAM_INV_CMD_TYPE);
                    push_packet_to_radio_tx_queue(ack_nack_csp_pckt, params->radio_tx_queue);
                    debug_printf_def_trace(debug, "Invalid command type.\n\r");
            }
            csp_buffer_free(rx_pckt);
        }
    }
}

void ham_build_ack_nack_csp_pckt(csp_packet_t *ack_nack_csp_pckt,const csp_id_t *src_pckt_id,const uint8_t type_code,const uint8_t msg_code) {
    
    ack_nack_csp_pckt->id.flags = 0x00;/* CSP_FCRC32; */
    ack_nack_csp_pckt->id.sport = src_pckt_id->dport;
    ack_nack_csp_pckt->id.dport = src_pckt_id->sport;
    ack_nack_csp_pckt->id.dst = src_pckt_id->src;
    ack_nack_csp_pckt->id.src = CSP_ADD_HAMRADIO_TASK;
    ack_nack_csp_pckt->id.pri = 0;

    ack_nack_csp_pckt->length = HAM_ACK_NACK_PCKT_LEN;
    ack_nack_csp_pckt->data[0] = type_code; 
    ack_nack_csp_pckt->data[1] = msg_code;
    // TODO : add delay before sending ? 
}

void ham_build_ham_csp_pckt(csp_packet_t *ham_csp_pckt, const ham_user_packet_t *data_to_send, const csp_id_t *src_pckt_id) {
    
    ham_csp_pckt->id.flags = 0x00; /* CSP_FCRC32; */
    ham_csp_pckt->id.sport = src_pckt_id->dport;
    ham_csp_pckt->id.dport = src_pckt_id->sport;
    ham_csp_pckt->id.dst = src_pckt_id->src;
    ham_csp_pckt->id.src = CSP_ADD_HAMRADIO_TASK;
    ham_csp_pckt->id.pri = 0;
    ham_csp_pckt->length=strnlen((char*)data_to_send,sizeof(ham_user_packet_t));

    memcpy(ham_csp_pckt->data,data_to_send,sizeof(ham_user_packet_t));
    ham_encrypt_pckt_data(ham_csp_pckt->data,ham_csp_pckt->length,(HAM_TAG_LEN+HAM_CRC_LEN+HAM_TIMESTAMP_LEN));
    
    // TODO : add delay before sending ? 
}

void ham_build_cache_csp_pckt(csp_packet_t *cache_csp_pckt,const csp_id_t *src_pckt_id,const uint8_t *data_to_send,const uint8_t data_len,const uint8_t cache_msg_nbr){

    cache_csp_pckt->id.flags = 0x00; /* CSP_FCRC32; */
    cache_csp_pckt->id.sport = src_pckt_id->dport;
    cache_csp_pckt->id.dport = src_pckt_id->sport;
    cache_csp_pckt->id.dst = src_pckt_id->src;
    cache_csp_pckt->id.src = CSP_ADD_HAMRADIO_TASK;
    cache_csp_pckt->id.pri = 0;
    cache_csp_pckt->length=data_len+sizeof(cache_msg_nbr);

    cache_csp_pckt->data[0]=cache_msg_nbr;
    memcpy(&cache_csp_pckt->data[1],data_to_send,data_len);
}

uint8_t ham_decrypt_pckt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start) {
    
    /* Get keys data from ham_messaging_sys_key file */
    extern uint8_t key[];
    extern uint8_t nbr_of_element_key[];
    extern uint8_t key_size;

    /* Decrypt the giving data array without including the crc. */
    uint16_t calculated_crc=0;
    uint8_t count=index_to_start;

        for (uint8_t i = index_to_start; i <data_len; i++)
        {
            for (uint8_t j = 0; j <key_size; j++)
            {
                if (key[j]==data[i])
                {   
                    data[count]=nbr_of_element_key[j];
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

void ham_encrypt_pckt_data(uint8_t *data, const uint8_t data_len,const uint8_t index_to_start) {
    
    /* Get keys data from ham_messaging_sys_key file */
    extern uint8_t key[];
    extern uint8_t nbr_of_element_key[];
    extern uint8_t key_size;

    /* Encrypt the given data without including the crc, timestamp and tag. */
    uint8_t data_key_index;
    uint8_t key_data=0;
    for (uint8_t i = index_to_start; i < data_len; i++)
    {
        uint8_t rand_nbr_limit=0;
        for (uint8_t j = 0; j < key_size; j++)
        {
            if(nbr_of_element_key[j]==data[i]){
                if (rand_nbr_limit==0)
                {
                    data_key_index=j;
                }
                rand_nbr_limit++; 
            }
        }
        key_data=data_key_index+(rand()%rand_nbr_limit);
        data[i]=key[key_data];
    }
}

void ham_update_data_from_eeprom(uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt,uint8_t pwd[],ham_msg_delay_t *msg_delay){
    
    ham_user_packet_t ham_pckt_eeprom ={0};
    uint8_t temp_pwd[HAM_PWD_LEN]={0};
    uint32_t temp_delay=0;
    uint8_t rv=0;

    /* Check and get stored messages from the eeprom. */
    for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
    {   
        memset(&ham_pckt_eeprom,0,sizeof(ham_user_packet_t));
        eeprom_read_byte_array(i+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));
        if (ham_pckt_eeprom.tag==HAM_MSG_SENT_TAG||ham_pckt_eeprom.tag==HAM_MSG_NOT_SENT_TAG)
        {
            ham_pckt_timestamp_cache[i]=ham_pckt_eeprom.timestamp;
            ham_pckt_id_cache[i][0]=ham_pckt_eeprom.tag;
            memcpy(&ham_pckt_id_cache[i][1],ham_pckt_eeprom.data.recipient_callsign,HAM_CALL_SIGN_LEN);
            memcpy(&ham_pckt_id_cache[i][7],ham_pckt_eeprom.data.sender_callsign,HAM_CALL_SIGN_LEN); 
            (*ham_pckt_cnt)++;  
        }
    }

    /* Check if there is a stored password in the eeprom. */
    eeprom_read_byte_array(HAM_PWD_ADDR,temp_pwd,HAM_PWD_LEN);
    rv =strncmp((char*)temp_pwd,"\0",HAM_PWD_LEN);
    if (rv)
    {
        memcpy(pwd,temp_pwd,HAM_PWD_LEN);
    }

    /* Check if there is a stored not sent message delay value in the eeprom. */
    eeprom_read_byte_array(HAM_NOT_SENT_MSG_DELAY_ADDR,(uint8_t*)&temp_delay,sizeof(temp_delay));
    rv =strncmp((char*)&temp_delay,"\0",sizeof(temp_delay));
    if (rv)
    {
        msg_delay->not_sent_msg=temp_delay;
    }

    /* Check if there is a stored sent message delay value in the eeprom. */
    eeprom_read_byte_array(HAM_SENT_MSG_DELAY_ADDR,(uint8_t*)&temp_delay,sizeof(temp_delay));
    rv =strncmp((char*)&temp_delay,"\0",sizeof(temp_delay));
    if (rv)
    {
        msg_delay->sent_msg=temp_delay;
    }
}

void ham_check_saved_msg_states(const ttc_handle_t *ttc_handle,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],const uint32_t ham_pckt_timestamp_cache[],const ham_msg_delay_t *msg_delay,uint8_t *ham_pckt_cnt){
    
    ham_user_packet_t ham_pckt_eeprom ={0};

    /* Check the timestamp of the packets and change the tag according to that. */
        for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
        {
            if (ham_pckt_id_cache[i][0]==HAM_MSG_SENT_TAG)
            {
                if ((ttc_handle->timestamp-ham_pckt_timestamp_cache[i])>=msg_delay->sent_msg)
                {
                    ham_pckt_id_cache[i][0]=HAM_MSG_ERASABLE_TAG;
                    eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));
                    /* Decrease the stored packet number. */
                    (*ham_pckt_cnt)--;
                }
            }
            else if (ham_pckt_id_cache[i][0]==HAM_MSG_NOT_SENT_TAG)
            {
                if ((ttc_handle->timestamp-ham_pckt_timestamp_cache[i])>=msg_delay->not_sent_msg)
                {
                    ham_pckt_id_cache[i][0]=HAM_MSG_ERASABLE_TAG;
                    eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));
                    /* Decrease the stored packet number. */
                    (*ham_pckt_cnt)--;
                }
            }
        }
}

void ham_handle_send_msg_cmd(const ham_msg_sys_task_params_t *params,const csp_id_t *rx_pckt_id,ham_user_packet_t *ham_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt, uint8_t debug){
                
                uint8_t rv=0;
                static uint8_t callsign_to_check[HAM_CALL_SIGN_LEN]={0};
                static csp_packet_t *ack_nack_csp_pckt = NULL;
                
                if((*ham_pckt_cnt) >= HAM_MAX_MSG_NBR) 
                {
                    /* The maximum number of message has been reached ! Creat NACK and advance the loop. */
                    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ack_nack_csp_pckt==NULL) return;
                    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_MAX_MSG_NBR_REACHED);
                    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,params->radio_tx_queue);
                    debug_printf_def_trace(debug, "The maximum number of message has been reached.\n\r");
                    return;
                }

                bool allowed_msg_nbr_reached=false;
                if ((*ham_pckt_cnt)>0)
                {   /* Checking how many message has stored the person. */
                    uint8_t allowed_msg_count=0;
                    for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
                    {   
                        if (ham_pckt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG) continue;
                        memcpy(&callsign_to_check,&ham_pckt_id_cache[i][7],HAM_CALL_SIGN_LEN);
                        rv=strncmp((char*)callsign_to_check,(char*)(ham_pckt->data.sender_callsign),HAM_CALL_SIGN_LEN);
                        if (rv==0)
                        {
                            allowed_msg_count++;
                            if (allowed_msg_count==HAM_ALLOWED_MSG_NBR)
                            {   
                                allowed_msg_nbr_reached=true;
                                break;
                            }
                        }
                    }
                }

                if (allowed_msg_nbr_reached==true)

                {   /* Creat NACK and advance the loop if the person has reached the allowed storable message number. */
                    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ack_nack_csp_pckt==NULL) return;
                    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_ALLOWED_MSG_NBR_REACHED);
                    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,params->radio_tx_queue);
                    debug_printf_def_trace(debug, "Allowed storable message number reached.\n\r");
                    return;
                }

                const uint8_t msg_len = strnlen((char*)(ham_pckt->data.message),HAM_MAX_MSG_LEN); 
                if (msg_len>HAM_MAX_MSG_LEN)
                {
                    /* The maximum length of the message exceeded ! Creat NACK and advance the loop. */
                    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ack_nack_csp_pckt==NULL) return;
                    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_MAX_MSG_LEN_EXCEED);
                    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,params->radio_tx_queue);
                    debug_printf_def_trace(debug, "The maximum length of the message exceeded.\n\r");
                    return;
                }
               

                for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
                {
                    if (ham_pckt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG)
                    {   
                        /* Set the tag to message not sent. */
                        ham_pckt->tag = HAM_MSG_NOT_SENT_TAG;
                        
                        /* Add the time stamp. */
                        ham_pckt->timestamp=params->ttc_handle->timestamp;

                        /* Store the call sign,time stamp and tag in the cache. */
                        ham_pckt_timestamp_cache[i]=params->ttc_handle->timestamp;
                        ham_pckt_id_cache[i][0]=ham_pckt->tag;
                        memcpy(&ham_pckt_id_cache[i][1],ham_pckt->data.recipient_callsign,HAM_CALL_SIGN_LEN);
                        memcpy(&ham_pckt_id_cache[i][7],ham_pckt->data.sender_callsign,HAM_CALL_SIGN_LEN);

                        /* Store the message in the eeprom ! Creat ACK and advance the loop. */
                        eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, (uint8_t*)ham_pckt, sizeof(ham_user_packet_t));
                        ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                        if (ack_nack_csp_pckt==NULL) return;
                        ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_MSG_STORED);
                        push_packet_to_radio_tx_queue(ack_nack_csp_pckt,params->radio_tx_queue);

                        /* Increase the packet number. */
                        (*ham_pckt_cnt)++;
                        debug_printf_def_trace(debug,"Message stored.\n\r");
                        break;
                    }
                }
}

void ham_handle_ask_msg_cmd(const ham_msg_sys_task_params_t *params,const csp_id_t *rx_pckt_id,const ham_user_packet_t *ham_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[], uint8_t debug){

                uint8_t search_state;
                uint32_t prev_timestamp;
                bool msg_search_init=false;
                uint8_t msg_to_send_addr;
                static csp_packet_t *ack_nack_csp_pckt = NULL;
                static csp_packet_t *ham_csp_pckt = NULL;
                ham_user_packet_t ham_pckt_eeprom ={0};
                static uint8_t callsign_to_check[HAM_CALL_SIGN_LEN]={0};

                for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
                { 
                    /* The packet tag is erasable so dont send it, advance the loop. */
                    if (ham_pckt_id_cache[i][0]==HAM_MSG_ERASABLE_TAG)
                    {
                        continue;
                    }

                    /* Search for the first message sent for the given person */
                    memcpy(&callsign_to_check,&ham_pckt_id_cache[i][1],HAM_CALL_SIGN_LEN);
                    search_state=strncmp((char*)callsign_to_check,(char*)(ham_pckt->data.sender_callsign),HAM_CALL_SIGN_LEN);
                    if (search_state==0)
                    {
                        if (prev_timestamp>ham_pckt_timestamp_cache[i]||msg_search_init==false)
                        {
                            prev_timestamp=ham_pckt_timestamp_cache[i];
                            msg_to_send_addr=i;
                            msg_search_init=true;
                        }
                    }
                }

                if (search_state==0)
                {
                    debug_printf_def_trace(debug, "Message Found.\n\r");

                    /* Message found send it. */
                    eeprom_read_byte_array(msg_to_send_addr+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));
                    ham_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ham_csp_pckt==NULL) return;
                    ham_build_ham_csp_pckt(ham_csp_pckt,&ham_pckt_eeprom,rx_pckt_id);
                    push_packet_to_radio_tx_queue(ham_csp_pckt,params->radio_tx_queue);

                    /* Change the tag of the packet to sent and re-store it. */
                    ham_pckt_eeprom.tag = HAM_MSG_SENT_TAG;
                    ham_pckt_id_cache[msg_to_send_addr][0]=ham_pckt_eeprom.tag;
                    eeprom_write_byte_array(msg_to_send_addr+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));

                    /* Update the timestamp of the packet. */
                    ham_pckt_timestamp_cache[msg_to_send_addr]=params->ttc_handle->timestamp;

                    debug_printf_def_trace(debug, "Message sent.\n\r");
                    return;
                }

                /* Message not found ? creat and send NACK. */
                debug_printf_def_trace(debug, "No Message.\n\r");
                ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                if (ack_nack_csp_pckt==NULL) return;
                ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_NO_MSG);
                push_packet_to_radio_tx_queue(ack_nack_csp_pckt, params->radio_tx_queue);
}

void ham_handle_get_cache_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,const uint8_t ham_pckt_id_cache[][HAM_ID_LEN],const uint32_t ham_pckt_timestamp_cache[],uint8_t ham_pckt_cnt, uint8_t debug){
                
                static csp_packet_t *ack_nack_csp_pckt = NULL;

                if (ham_pckt_cnt==0)
                {
                    /* No cache data to send ? creat and send NACK. */
                    debug_printf_def_trace(debug,"No cache data.\n\r");
                    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (ack_nack_csp_pckt==NULL) return;
                    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_NO_SAVED_MSG);
                    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
                    return;
                }

                /* Sending all the data stored in the cache to the user. */
                debug_printf_def_trace(debug,"Sending cache data.\n\r");

                /* Calculate the number of csp packet needed to be created for sending all the data considering the maximum size of the data field of a CSP packet. */
                static csp_packet_t *cache_csp_pckt = NULL;
                uint8_t nbr_of_pckt_to_be_created=(ham_pckt_cnt-(ham_pckt_cnt%HAM_MAX_CACHE_MSG_NBR))/HAM_MAX_CACHE_MSG_NBR;
                uint8_t i=0;

                for (uint8_t j = 0; j <= nbr_of_pckt_to_be_created; j++)
                {
                    uint8_t cache_data_to_send[TTC_CSP_BUFFER_DATA_SIZE-TTC_CSP_CRC_FIELD_LEN]={0};
                    uint8_t cache_count=0;
                    for (; i < HAM_MAX_MSG_NBR; i++)
                    {
                        /* Check if the packet is full. */
                        if (cache_count==HAM_MAX_CACHE_MSG_NBR)
                        {
                            break;
                        }
                        if (ham_pckt_id_cache[i][0]==HAM_MSG_SENT_TAG||ham_pckt_id_cache[i][0]==HAM_MSG_NOT_SENT_TAG)
                        {
                            /* Fill the data to send with just the cache data that has sent and not sent tag. */
                            memcpy(&cache_data_to_send[0+(HAM_CACHE_MSG_DATA_LEN*cache_count)],&ham_pckt_id_cache[i][0],(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN);
                            memcpy(&cache_data_to_send[(2*HAM_CALL_SIGN_LEN)+HAM_TAG_LEN+(HAM_CACHE_MSG_DATA_LEN*cache_count)],&ham_pckt_timestamp_cache[i],HAM_TIMESTAMP_LEN);
                            cache_count++;
                        }
                    }

                    /* Creat and send packet. */
                    cache_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                    if (cache_csp_pckt==NULL) return;
                    ham_build_cache_csp_pckt(cache_csp_pckt,rx_pckt_id,cache_data_to_send,(HAM_CACHE_MSG_DATA_LEN*cache_count),cache_count);
                    push_packet_to_radio_tx_queue(cache_csp_pckt,radio_tx_queue);
                }
}

void ham_handle_upd_not_sent_msg_delay_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint32_t *msg_delay,uint8_t debug){
    
    static csp_packet_t *ack_nack_csp_pckt = NULL;

    const uint8_t msg_delay_len=strnlen((char*)ham_pckt->data,HAM_ADMIN_PCKT_DATA_LEN);

    /* Check if lengt of the sent value is greater than HAM_MSG_MAX_DELAY_LEN. */
    if (msg_delay_len>HAM_MSG_MAX_DELAY_LEN)
    {
        ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
        if (ack_nack_csp_pckt==NULL) return;
        ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_MSG_MAX_DELAY_LEN_EXCEED);
        push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
        debug_printf_def_trace(debug, "The length of the delay value sent is to long.\n\r");
        return;
    }

    *msg_delay=atoi((char*)ham_pckt->data);

    /* Message delay is changed, save the change in the eeprom, creat and send ACK. */
    debug_printf_def_trace(debug, "Not sent message delay updated successfully.\n\r");
    eeprom_write_byte_array(HAM_NOT_SENT_MSG_DELAY_ADDR,(uint8_t*)msg_delay,sizeof(uint32_t));
    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
    if (ack_nack_csp_pckt==NULL) return;
    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_NOT_SENT_MSG_DELAY_UPD);
    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
}

void ham_handle_upd_sent_msg_delay_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint32_t *msg_delay,uint8_t debug){
    
    static csp_packet_t *ack_nack_csp_pckt = NULL;

    const uint8_t msg_delay_len=strnlen((char*)ham_pckt->data,HAM_ADMIN_PCKT_DATA_LEN);

    /* Check if lengt of the sent value is greater than HAM_MSG_MAX_DELAY_LEN. */
    if (msg_delay_len>HAM_MSG_MAX_DELAY_LEN)
    {
        ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
        if (ack_nack_csp_pckt==NULL) return;
        ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_MSG_MAX_DELAY_LEN_EXCEED);
        push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
        debug_printf_def_trace(debug, "The length of the delay value sent is to long.\n\r");
        return;
    }

    *msg_delay=atoi((char*)ham_pckt->data);

    /* Message delay is changed, save the change in the eeprom, creat and send ACK. */
    debug_printf_def_trace(debug, "Sent message delay updated successfully.\n\r");
    eeprom_write_byte_array(HAM_SENT_MSG_DELAY_ADDR,(uint8_t*)msg_delay,sizeof(uint32_t));
    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
    if (ack_nack_csp_pckt==NULL) return;
    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_SENT_MSG_DELAY_UPD);
    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
}

void ham_handle_del_all_msg_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint8_t *ham_pckt_cnt,uint8_t debug){    
    
    ham_user_packet_t ham_pckt_eeprom ={0};
    static csp_packet_t *ack_nack_csp_pckt = NULL;

    if (ham_pckt_cnt==0)
        {
            /* Creat and send NACK. */
            ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
            if (ack_nack_csp_pckt==NULL) return;
            ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_NACK,HAM_NO_SAVED_MSG);
            push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
            debug_printf_def_trace(debug,"No message to deleted.\n\r");
            return;
        }
    
    for (uint8_t i = 0; i < HAM_MAX_MSG_NBR; i++)
        {
            if (ham_pckt_id_cache[i][0]==HAM_MSG_SENT_TAG||ham_pckt_id_cache[i][0]==HAM_MSG_NOT_SENT_TAG)
            {   
                /* Clean the cache and the eeprom. */
                ham_pckt_id_cache[i][0]=HAM_MSG_ERASABLE_TAG;
                eeprom_write_byte_array(i+HAM_MSG_EEPROM_ADDR, (uint8_t*)&ham_pckt_eeprom, sizeof(ham_user_packet_t));
                
                /* Decrease the stored packet number. */
                (*ham_pckt_cnt)--;
            }
        }
    /* Creat and send ACK. */
    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
    if (ack_nack_csp_pckt==NULL) return;
    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_ALL_MSG_DELETED);
    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
    debug_printf_def_trace(debug,"All messages have been deleted.\n\r");
}

void ham_handle_upd_pwd_cmd(const QueueHandle_t radio_tx_queue,const csp_id_t *rx_pckt_id,ham_admin_packet_t *ham_pckt,uint8_t pwd[],uint8_t debug){
    
    static csp_packet_t *ack_nack_csp_pckt = NULL;
    uint8_t first_new_pwd[HAM_PWD_LEN]={0};
    uint8_t second_new_pwd[HAM_PWD_LEN]={0};
    uint8_t rv=0;

    /* Check if the two password are identical. */
    memcpy(first_new_pwd,&ham_pckt->data[0],HAM_PWD_LEN);
    memcpy(second_new_pwd,&ham_pckt->data[HAM_PWD_LEN],HAM_PWD_LEN);
    rv=strncmp((char*)first_new_pwd,(char*)second_new_pwd,HAM_PWD_LEN);
    if (rv)
    {
        ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
        if (ack_nack_csp_pckt==NULL) return;
        ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_PWD_NOT_EQ);
        push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
        debug_printf_def_trace(debug,"Passwords not equal.\n\r");
        return;
    }

    /* Assigne the new password instead of the old one and save it in the eeprom. */
    memcpy(pwd,&ham_pckt->data[0],HAM_PWD_LEN);
    eeprom_write_byte_array(HAM_PWD_ADDR,pwd,HAM_PWD_LEN);

    /* Creat and send ACK. */
    ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
    if (ack_nack_csp_pckt==NULL) return;
    ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,rx_pckt_id,RADIO_ACK_CODE_ACK,HAM_PWD_CHANGED);
    push_packet_to_radio_tx_queue(ack_nack_csp_pckt,radio_tx_queue);
    debug_printf_def_trace(debug,"Password changed successfully.\n\r");
}

void ham_handle_user_cmd(const ham_msg_sys_task_params_t *params,const csp_packet_t *rx_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint32_t ham_pckt_timestamp_cache[],uint8_t *ham_pckt_cnt,uint8_t debug){
                
    static csp_packet_t *ack_nack_csp_pckt = NULL;
    ham_user_packet_t ham_pckt ={0};
    memcpy(&(ham_pckt.data), rx_pckt->data, sizeof(ham_user_pckt_data_t));
    
    /* Check the command. */
    switch (ham_pckt.data.command)
    {
        case HAM_SEND_MSG_CMD:
            ham_handle_send_msg_cmd(params,&(rx_pckt->id),&ham_pckt,ham_pckt_id_cache,ham_pckt_timestamp_cache,ham_pckt_cnt,debug);
            break;
        case HAM_ASK_MSG_CMD:
            ham_handle_ask_msg_cmd(params,&(rx_pckt->id),&ham_pckt,ham_pckt_id_cache,ham_pckt_timestamp_cache,debug);
            break;
        case HAM_GET_CACHE_CMD:
            ham_handle_get_cache_cmd(params->radio_tx_queue,&(rx_pckt->id),ham_pckt_id_cache,ham_pckt_timestamp_cache,*ham_pckt_cnt,debug);
            break;
        default:
            /* Invalid command ! Creat and send NACK. */
            ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
            if (ack_nack_csp_pckt==NULL) return;
            ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,&(rx_pckt->id),RADIO_ACK_CODE_NACK,HAM_INV_CMD);
            push_packet_to_radio_tx_queue(ack_nack_csp_pckt, params->radio_tx_queue);
            debug_printf_def_trace(debug, "Invalid command.\n\r");
    }
}

void ham_handle_admin_cmd(const ham_msg_sys_task_params_t *params,const csp_packet_t *rx_pckt,uint8_t ham_pckt_id_cache[][HAM_ID_LEN],uint8_t *ham_pckt_cnt,ham_msg_delay_t *msg_delay,uint8_t pwd[],uint8_t debug){
    
    uint8_t rv=0;
    static csp_packet_t *ack_nack_csp_pckt = NULL;
    ham_admin_packet_t ham_pckt ={0};
    memcpy(&(ham_pckt), rx_pckt->data, sizeof(ham_admin_packet_t));
                
    rv=strncmp((char*)ham_pckt.pwd,(char*)pwd,HAM_PWD_LEN);
    if (rv==0)
    {
        /* Check the command. */
        switch (ham_pckt.command)
        {
            case HAM_DEL_ALL_MSG_CMD:
                ham_handle_del_all_msg_cmd(params->radio_tx_queue,&(rx_pckt->id),ham_pckt_id_cache,ham_pckt_cnt,debug);
                break;
            case HAM_UPD_NOT_SENT_MSG_DELAY_CMD:
                ham_handle_upd_not_sent_msg_delay_cmd(params->radio_tx_queue,&(rx_pckt->id),&ham_pckt,&(msg_delay->not_sent_msg),debug);
                break;
            case HAM_UPD_SENT_MSG_DELAY_CMD:
                ham_handle_upd_sent_msg_delay_cmd(params->radio_tx_queue,&(rx_pckt->id),&ham_pckt,&(msg_delay->sent_msg),debug);
                break;
            case HAM_UPD_PWD_CMD:
                ham_handle_upd_pwd_cmd(params->radio_tx_queue,&(rx_pckt->id),&ham_pckt,pwd,debug);
                break;
            default:
                /* Invalid command ! Creat and send NACK. */
                ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
                if (ack_nack_csp_pckt==NULL) return;
                ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,&(rx_pckt->id),RADIO_ACK_CODE_NACK,HAM_INV_CMD);
                push_packet_to_radio_tx_queue(ack_nack_csp_pckt, params->radio_tx_queue);
                debug_printf_def_trace(debug, "Invalid command.\n\r");
        }
    }
    else
    {
        /* Invalid password ! Creat and send NACK. */
        ack_nack_csp_pckt = csp_buffer_get(csp_buffer_data_size());
        if (ack_nack_csp_pckt==NULL) return;
        ham_build_ack_nack_csp_pckt(ack_nack_csp_pckt,&(rx_pckt->id),RADIO_ACK_CODE_NACK,HAM_INV_PWD);
        push_packet_to_radio_tx_queue(ack_nack_csp_pckt, params->radio_tx_queue);
        debug_printf_def_trace(debug, "Invalid password.\n\r");
    }
}