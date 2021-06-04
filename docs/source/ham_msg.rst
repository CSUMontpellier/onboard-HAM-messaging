.. _firmware-tasks-hamradio-messaging-task:

Messaging System
================

Overview
--------

The HAM Radio Messaging System provides a message-exchanging service between Amateur Radio Users using Robusta satellite missions as relays. The main purpose of the system is to enable HAM Radio operators to send and receive messages from anywhere in the world without having a direct (end-to-end) connection  between them. 
The Messaging System uses a method called ‘store and forward’ to provide this service. Messages are transported to the relay station (satellite) by a radio link, and from one geographical location to another, by the satellite orbital movement. An user sends a message to the satellite during a pass and the message is stored in the satellite's memory. The satellite then moves in its orbit, making the stored message available for other HAM Radio operators. Users can request messages to the satellite which, in turn will check if there are any stored messages available for that particular operator. Finally, the message is transmitted and it arrives at its destination.

.. figure:: /_static/ham.gif
      :width: 80%
      :align: center
      :alt: HAM radio Messaging System Task Flow Diagram

Robusta 3A TT&C
---------------

The ROBUSTA 3A Satellite consists of different subsystems that are in charge of performing specific functions onboard the platform. In the context of the HAM Radio messaging system, the TT&C (Telemetry, Tracking and Control) subsystem is the core component that enables the exchange of data between ground stations through an RF link. In addition, this link will enable the Mission Control Center (MCC)/User to bidirectionally communicate with the satellite for receive data and send commands to the satellite to perform actions.

The embedded software (firmware) of the TT&C is implemented on top of `FreeRTOS <https://www.freertos.org/>`_ (Real-time operating system). In freeRTOS, the application is segmented into `FreeRTOS tasks <https://www.freertos.org/a00015.html>`_ which are executed periodically. These tasks perform specific functions of the global application. The TT&C has several tasks which enable the forwarding of messages between the Ground Segment and the rest of the platform. In the context of the HAM Radio Messaging System, it is important to take into account the following tasks:

- **Radio Interface Task**: Implements the interface with the radio transceivers, and orchestrates the reception and transmission of data packets. The received packets are then forwarded to the Radio RX Processing Task.

- **Radio RX Processing Task**: Parses all the incoming :ref:`Radio Packets <RP>` from the Radio Interface Task and executes the commands accordingly.

- **HAM Radio Messaging System Task**: Implements the HAM Radio Messaging System. This task accepts packets from the Radio RX Processing Task and process them to store messages or read messages.

In the figure below we can see the flow of a Radio Packet from the Ground Segment to the HAM Radio messaging system.

.. figure:: /_static/gs_ham_task_flow.svg
      :scale: 110 %
      :align: center
      :alt: Packets flow from Ground segment to the HAM Radio messaging system

In freeRTOS, a common way of exchanging data between tasks is through Queues. A queue can be seen as an array of data that is filled in FIFO fashion. One task produces data and fills in the queue while another task consumes the data (removes from the queue). HAM Radio Messaging System Task use these following Queues to transfer data between tasks:

.. list-table:: Queues Definition Table
   :name: ham-queues-definition-table
   :header-rows: 1
   :widths: 10 10 60
   :stub-columns: 1

   *  -  Name
      -  Data
      -  Description
   *  - radio_tx_queue
      - csp_packet_t *
      - Stores the data that shall be transmitted by the radio through the RF path
   *  - hamradio_packet_rx_queue
      - csp_packet_t *
      - Stores the HAM Radio packets received and needing to be processed.
   *  - event_queue
      - ttc_event_t
      - Stores the event codes found in each subsystem.

The TT&C firmware use :ref:`CSP <CSP>` (Cubesat Space Protocol) while exchanging data between tasks through queues and between GS/User through the RF path. The communication of the satellite on the first hand is handled from the Radio Interface Task and Radio RX Processing Task. The Radio Interface Task is continuously checking if any :ref:`Radio Packet <RP>` have been received by the radio and on the other side, it is monitoring the :ref:`Radio TX Queue <ham-queues-definition-table>` to check if there are Radio Packets that need to be transmitted by the radio. The Radio RX Processing Task gets the received radio packet from the Radio Interface Task and, based on the packet destination, pushes it to the appropriate destination for its next task. For example if a Radio Packet is received and its destination is the HAM Radio Messaging System Task, the Radio RX Processing Task will push this Radio Packet to the :ref:`HAMRadio Packet RX Queue <ham-queues-definition-table>` .

The HAM Radio Messaging System Task is continuously checking the state of all stored messages and monitoring the :ref:`HAMRadio Packet RX Queue <ham-queues-definition-table>` to check if any :ref:`HAM Radio Packets <HAMP>` have been received. When that happens, the HAM Radio Messaging System Task pulls the received packet from the queue and checks its validity. In order to ensure that messages are delivered to the correct user, the raw strings sent and received by amateur radios are pseudo-encrypted using a chipher algorithm.

Users who wish to exchange messages using the satellite will need to send a specific set of data depending on the operation they want to execute:

- **Write Message**: To send a message to another person the user needs to create and configure the HAM Radio Packets as given in the section :ref:`HAM Radio Packets <HAMP>` . When the user sends this packet and the satellite receives it, the HAM Radio Messaging System Task will check the HAM CRC, message length , how many messages contain the current users call sign and the total number of stored messages, then it will store the message. These constraints have predefined values and can be viewed in the :ref:`Message Constraints and Constants Table <CONS>` .

- **Read Message**: To ask if there is a message for a specific person, the user needs to create and configure a HAM Radio Packet as given in the section :ref:`HAM Radio Packets <HAMP>`. When the user sends this packet and the satellite receives it, the HAM Radio Messaging System Task will send the message to the :ref:`Radio TX Queue <ham-queues-definition-table>` if there is a message for the requested call sign (therefore the requesting user).

Depending on the operation that is being executed, the satellite will reply with :ref:`ACK/NACK <ACK>` packets to the ground.

- **Files**:
    - source/hamradio_messaging_system_task.c
    - source/hamradio_messaging_system_task.h

.. _CSP:

Cubesat Space Protocol
----------------------

Cubesat Space Protocol (CSP) is a network library that implement a small protocol stack over the hardware network interface. This protocol is similar to the internet protocol. The Robusta satellite uses this protocol to establish the communication between the task, the subsystems and GS/User. The stack of data sent and received with this protocol are called CSP packets and they are exchanged between source and destination nodes and between source and destination port. This way the packet can be redirected to a specific task inside a satellite's board. This protocol can use various typical embedded networks such as CAN, I2C, SPI or even UART.

CSP provides a documentation to set up a CSP client and exchange packets. This documentation can be found in `/libcsp <https://github.com/libcsp/libcsp>`_

.. figure:: /_static/CSP_protocol.svg
      :scale: 110 %
      :align: center
      :alt: CSP Packet

The above figure describes the composition of the CSP packet, and it consists of two parts, the header and the data field. The 32 bit header contains source and destination addresses, source and destination ports and basic means for authentication(HMAC), encryption(XTEA), UDP/RDP-like connections, and checksums(CRC). The header part is used to identify the sender and the recipient of the task or user. The data field is the data to send.

.. _RP:

**Radio Packet**:

The data send to the Robusta satellite and receive from the satellite is a CSP packet, with the length of the data to send included in the data field, and it's referred as Radio Packet. Information about the radio packet is given below.

.. figure:: /_static/radio_packet.svg
      :scale: 110 %
      :align: center
      :alt: Radio Packet

In the figure above we can see the composition of a Radio Packet. The Data field must include as the first two byte the length of the data to send, then comes the data to send. The field 'Data to send' will be the HAM Radio message to be send, but for this the field need to be configured in a specific manner, look into the :ref:`HAM Radio Packet<HAMP>` section. Information and value about the CSP header fields are given below.

.. list-table:: CSP header
   :align: center
   :header-rows: 1
   :widths: 10 10 60

   *  -  Field name
      -  Description
      -  Value
   *  - Priority
      - The priority of the packet
      - 0x02
   *  - Source address
      - The address of the sender
      - 0x1D
   *  - Destination address
      - The address of the HAM Radio Messaging System Task
      - 0x09
   *  - Destination port
      - The port number of the HAM Radio Messaging System Task
      - 0x01
   *  - Source port
      - The port number of the sender
      - 0x01
   *  - HMAC
      - Hash-based message authentication code
      - 0x00
   *  - XTEA
      - Data field encryption with extended tiny encryption algorithm
      - 0x00
   *  - RDP
      - Reliable datagram protocol
      - 0x00
   *  - CRC
      - Checksum for error detection
      - 0x01


If the CRC flag is set to true a CRC must be calculated and added at the end of the radio packet data field as in the figure below.

.. figure:: /_static/radio_packet_crc.svg
      :scale: 110 %
      :align: center
      :alt: Radio packet with CRC

.. _HAMP:

HAM Radio Packet
----------------

The HAM Radio Packet is basically a :ref:`Radio Packet <RP>` where the 'data to send' field is configured in a specific manner. The 'data to send' field can have different configurations, and those configurations can be seen in the section below.

**Write Message**:

.. figure:: /_static/ham_sending_message.svg
      :scale: 120 %
      :align: center
      :alt: Message sending configuration


This 'data to send' field configuration shown above is used to send a message to another user. The 'HAM CRC' is a value to check if the message changed since it was sent to the satellite, it is automatically calulated from the :ref:`encryption sofware <ENCR>` . The 'Command Type' must be set to 's' to send a message. The 'Sender Call Sign' is the call sign of the user who is sending the message, the 'Recipient Call Sign' is the call sign of the user supposed to receive the message and the 'Message' part is the message to transmit.

**Read Message**:

.. figure:: /_static/ham_asking_message.svg
      :scale: 120 %
      :align: center
      :alt: Message asking configuration

This 'data to send' field configuration shown above is used to ask the satellite if there is a message for the requesting user. The 'Command Type' must be set to 'g' to ask for a  message. The 'Sender Call Sign' is the call sign for which the satellite will match stored messages.

**Stored Message**:

.. figure:: /_static/ham_message_sat.svg
      :scale: 120 %
      :align: center
      :alt: Data field configuration when the message is stored in the satellite or sent to user from the satellite

This 'data to send' field configuration shown above is used when the message is stored in the satellite or sent to a user from the satellite. It is basically what you will get in the :ref:`Radio Packet <RP>` 'data to send' field when the sattelite found a message matching your request, therefore your call sign matches a messages Recipient Call Sign. After the reception and validation of the HAM Radio Packet the HAM Radio Messaging System Task will additionally add a 'Message Tag' and 'Timestamp' to the packet before storing it. The 'Timestamp' is the number of seconds that have elapsed since January 1, 1970 (midnight UTC/GMT), its providing information about when the message was sent. The 'Message tag' is used for checking the state of stored message. More details about the 'Message Tag' can be found in the table below. 

.. list-table:: HAM Radio Packet Tag
   :align: center
   :header-rows: 1

   *  - Message Tag name
      - Description
      - Value
   *  - Sent
      - Tag of the message indicating that it was sent
      - 0x02
   *  - Not sent
      - Tag of the message indicating that it was not sent
      - 0x01
   *  - Erasable
      - Tag of the message indicating that it can be replaced by another message
      - 0x00
      
**Call Signs**:

Call signs are already used to identify a HAM Radio station or operator. Based on this the HAM Radio Messaging System Task also use call sign to identify users. In the figure below we can see a call sign, it consist of two parts 'Prefix' and 'Serial letters'.

.. figure:: /_static/callsign.svg
      :scale: 120 %
      :align: center
      :alt: Call sign

.. _ACK:

HAM Radio ACK/NACK Packet
-------------------------
When data is transmitted between two systems, an acknowledgement (ACK) can be sent to confirm an action and a negative-acknowledgment (NACK) can be sent to report an error. Based on the situation the HAM Radio Messaging System Task replies with a ACK/NACK packet to inform the GS/User. For example if you send a HAM radio packet with 'Write Message' command and your packet is valid, the satellite will reply you with an ACK packet. There are several different processes which reply with a ACK/NACK packet, those can be seen in the  :ref:`diagram` .

.. figure:: /_static/ham_ack.svg
      :scale: 110 %
      :align: center
      :alt: ACK/NACK packet Data field configuration

The HAM Radio Messaging System Task also uses the :ref:`Radio Packet <RP>` with 2 bytes in the 'data to send' field to creat ACK/NACK packets. In the figure above we can see the ACK/NACK packet. The first field, 'Type Code', is used to identify the type of the packet. The second field, 'ACK/NACK packet message code', is used to identify the message that give more details about the ACK/NACK. More informations about the fields of the ACK/NACK packet can be seen in the tables below.

.. table:: ACK/NACK packet type
   :widths: auto
   :align: center

   =====================  =========================
   ACK/NACK packet type   ACK/NACK packet type code
   =====================  =========================
    ACK                    0x01
    NACK                   0x02
   =====================  =========================

.. table:: ACK/NACK packet message
   :widths: auto
   :align: center

   ==== ============================ ====================================================================
   Type ACK/NACK packet message code ACK/NACK packet message
   ==== ============================ ====================================================================
   ACK     0x03                      Message is stored
   NACK    0x04                      Invalid command
   NACK    0x05                      Storable maximum message number has been reached
   NACK    0x06                      Invalid HAM Radio packet
   NACK    0x07                      No message for the given call sign
   NACK    0x08                      Maximum length of the message exceeded
   NACK    0x09                      Allowed number of storable message for the person has been reached
   NACK    0x0A                      Message deleted
   ==== ============================ ====================================================================

.. _ENCR:

HAM Radio Message Encryption
------------------------------

The HAM Radio Message Encryption is used in order to ensure that messages are delivered to the correct user. Before the user sends a message, the 'data to send' field of the :ref:`HAM Radio Packet <HAMP>` is pseudo-encrypted with a cipher algorithm and a HAM CRC is automatically calculated and added to be sure that the message is not changed. After reception the satellite checks the CRC and the validity of the HAM Radio packet and store the Packet without decrypting it and sends it, in this case, to users. After receiving the HAM Radio Packet the user must decrypt the 'data to send' field to read the message correctly.

.. _CONS:

HAM Radio Message Constraints and Constants
-------------------------------------------

The constraints and constants concerning HAM Radio messages are listed in the table below.

.. list-table::
   :align: center
   :header-rows: 1
   :widths: 10 60

   *  -  Constraint/Constants
      -  Value
   *  - The maximum allowed length of the message (in bytes)
      - 20
   *  - The maximum number of storable messages in the satellite
      - 20
   *  - The maximum number of messages a person can store
      - 1
   *  - The length of the call sign (in bytes)
      - 6
   *  - The time given before deleting messages with the sent tag (in seconds)
      - 15
   *  - The time given before deleting messages with the not sent tag (in seconds)
      - 86400
   *  - The length of the ACK/NACK packet (in bytes)
      - 2
   *  - Byte to identify the write message command
      - s
   *  - Byte to identify the read message command
      - g

Functional Diagram
---------------------

.. figure:: /_static/HAMradio_task_diagram.svg
      :name: diagram
      :width: 90%
      :align: center
      :alt: HAM radio Messaging System Task Flow Diagram

      HAM radio Messaging System Task Flow Diagram

Main functions
-----------------

* Receiving packets
    * Check the state of stored messages
    * Check if the given time for stored messages has been exceeded
    * Check if HAM Radio packet are received
    * Decrypt received packets
    * Check packets validity
    * Check command type
        * Write message
            * Check the message length
            * Check how many messages the sender of this message has stored
            * Check the number of total stored messages
        * Read message
            * Check if there is a message for the given user
    * Create HAM Radio packets.
    * Create ACK/NACK packets
    * Push packets to the :ref:`Radio TX Queue <ham-queues-definition-table>`
* Push errors to Event Queue

Accessed Resources
------------------

EEPROM for storing messages

Data Interfaces
---------------

- :ref:`Radio TX Queue <ham-queues-definition-table>`
- :ref:`HAMRadio Packet RX Queue <ham-queues-definition-table>`
- :ref:`Event Queue <ham-queues-definition-table>`
