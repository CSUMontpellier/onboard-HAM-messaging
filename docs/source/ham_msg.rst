.. _firmware-tasks-hamradio-messaging-task:

HAM Radio Messaging System
==========================

Overview
--------

The HAM radio messaging system provides a message-exchanging service between amateur radio users using Robusta satellite missions as relays. The main purpose of the system is to enable HAM radio operators to send and receive messages from anywhere in the world without having a direct (end-to-end) connection  between them.
The messaging system uses a method called ‘store and forward’ to provide this service. Messages are transported to the relay station (satellite) by a radio link, and from one geographical location to another, by the satellite orbital movement. An user sends a message to the satellite during a pass and the message is stored in the satellite's memory. The satellite then moves in its orbit, making the stored message available for other HAM radio operators. Users can request messages to the satellite which, in turn will check if there are any stored messages available for that particular operator. Finally, the message is transmitted and it arrives at its destination.

.. figure:: /_static/ham.gif
      :width: 40%
      :align: center
      :alt: HAM radio messaging system task packet flow diagram

Robusta 3A TT&C
---------------

The ROBUSTA 3A satellite consists of different subsystems that are in charge of performing specific functions onboard the platform. In the context of the HAM radio messaging system, the TT&C (Telemetry, Tracking and Control) subsystem is the core component that enables the exchange of data between ground stations through an RF link. In addition, this link will enable the mission control center (MCC)/User to bidirectionally communicate with the satellite for receive data and send commands to the satellite to perform actions.

The embedded software (firmware) of the TT&C is implemented on top of `FreeRTOS <https://www.freertos.org/>`_ (Real-time operating system). In freeRTOS, the application is segmented into `FreeRTOS tasks <https://www.freertos.org/a00015.html>`_ which are executed periodically. Each of these tasks performs specific functions of the global application. The TT&C has several tasks which enable the forwarding of data between the ground segment and the rest of the platform. In the context of the HAM radio messaging system, it is important to take into account the following tasks:

- **Radio Interface Task**: Implements the interface with the radio transceivers, and orchestrates the reception and transmission of data packets. The received packets are then forwarded to the radio RX processing task.

- **Radio RX Processing Task**: Parses all the incoming :ref:`radio packets <RP>` from the radio interface task and dispatch them to the corresponding handler.

- **HAM Radio Messaging System Task**: Implements the HAM radio messaging system. This task accepts :ref:`HAM radio packets <HAMP>` from the radio RX processing task, sends :ref:`HAM radio Packets <HAMP>` to the radio interface task and performs different operations according to the received command.

In the figure below we can see the flow of a radio packet sent from the ground segment to the HAM radio messaging system and vice-versa.

.. figure:: /_static/gs_ham_task_flow.svg
      :scale: 110 %
      :align: center
      :alt: Packets flow from the ground segment to the HAM radio messaging system and vice-versa.

In freeRTOS, a common way of exchanging data between tasks is through Queues. A queue can be seen as an array of data that is filled in FIFO fashion. One task produces data and fills in the queue while another task consumes the data (removes from the queue). HAM radio messaging system task use these following Queues to transfer data between tasks:

.. list-table:: Queues Definition Table
   :name: ham-queues-definition-table
   :header-rows: 1
   :widths: 10 10 60
   :stub-columns: 1

   *  - Name
      - Data
      - Description
   *  - radio_tx_queue
      - csp_packet_t *
      - Stores the data that shall be transmitted by the radio through the RF path
   *  - hamradio_packet_rx_queue
      - csp_packet_t *
      - Stores the HAM radio packets received and needing to be processed.
   *  - event_queue
      - ttc_event_t
      - Stores the event codes found in each subsystem.

The TT&C firmware use :ref:`CSP <CSP>` (Cubesat Space Protocol) while exchanging data between tasks through queues and between GS/User through the RF path. The communication of the satellite on the first hand is handled from the radio interface Task and radio RX processing task. The radio interface task is continuously checking if any :ref:`radio packet <RP>` have been received by the radio and on the other side, it is monitoring the :ref:`radio TX queue <ham-queues-definition-table>` to check if there are radio packets that need to be transmitted by the radio. The radio RX processing task gets the received radio packet from the radio interface task and based on the packet destination, pushes it to the appropriate queue for its next task. For example if a radio packet is received and its destination is the HAM radio messaging system task, the radio RX processing task will push this radio packet to the :ref:`HAM radio packet RX queue <ham-queues-definition-table>`.

The HAM radio messaging system task is continuously checking the state of all stored messages and monitoring the :ref:`HAM radio packet RX Queue <ham-queues-definition-table>` to check if any :ref:`HAM radio packets <HAMP>` have been received. When that happens, the HAM radio messaging system task pulls the received packet from the queue and checks its validity. According to command type and command of the HAM radio packet sent, the HAM radio messaging system task will carry out different operations.

.. figure:: /_static/ham_com.svg
      :scale: 150 %
      :align: center
      :alt: HAM radio communication


Depending on the operation that is being executed, the HAM radio messaging system task will reply with a :ref:`HAM radio packet <HAMP>` or 
a :ref:`ACK/NACK packet <ACK>` to the ground.

**Main functions of the HAM radio messaging system task**:

* Receiving packets
    * Check the state of stored messages
    * Check if the given time for stored messages has been exceeded
    * Check the :ref:`HAM radio packet rx queue <ham-queues-definition-table>` if HAM Radio packet are received
    * Decrypt received packets
    * Check packets validity
    * Check command type
    * Check command
    * Execute operations
    * Save data to eeprom
* Transmitting packets
    * Read data from eeprom
    * Create HAM Radio packets.
    * Create ACK/NACK packets
    * Encrypt packets
    * Push packets to the :ref:`radio TX queue <ham-queues-definition-table>`
* Push errors to Event Queue

For more detailed information about the operation of the system, you can examine the :ref:`functional diagram <FD>`.

**Accessed Resources**:
    - :ref:`EEPROM <EEP>`

**Files**:
    - `hamradio_messaging_system_task.c <https://github.com/CSUMontpellier/onboard-HAM-messaging/blob/dev/source/ham_messaging_sys_task.c>`_
    - `hamradio_messaging_system_task.h <https://github.com/CSUMontpellier/onboard-HAM-messaging/blob/dev/source/ham_messaging_sys_task.h>`_

Using The HAM Radio Messaging System
------------------------------------
Users who wish to exchange messages or communicate with the HAM radio messaging system will need to send a specific data set depending on the operation 
they want to execute. These data sets are called :ref:`HAM radio packets <HAMP>`.
User must create and configure they HAM radio packets as given in the section :ref:`HAM radio packets <HAMP>` using the :ref:`data diffusion platform <DDP>`.
After the creation of the HAM radio packet users can use their own RF communication system to send them to the satellite. 

.. figure:: /_static/ham_steps.svg
      :scale: 100 %
      :align: center
      :alt: HAM radio messaging system flow


In the figure above we can see the steps to flow for communicate with the HAM radio messaging system.

In order to ensure the security of the communication the packets sent are pseudo-encrypted using a cipher algorithm so when users receive a HAM radio packet 
as the response of an 'ask message' command they must decrypt the encrypted part of this packet with the help of the 
:ref:`data diffusion platform <DDP>` in order to read the message it contain.

More details about the encryption can be found in the :ref:`HAM radio packet encryption <ENCR>` section.

.. _CSP:

Cubesat Space Protocol
----------------------

Cubesat Space Protocol (CSP) is a network library that implement a small protocol stack over the hardware network interface. 
This protocol is similar to the internet protocol. The Robusta satellite uses this protocol to establish the communication between the task, 
the subsystems and GS/User. The stack of data sent and received with this protocol are called CSP packets and they are exchanged between source 
and destination nodes and between source and destination port. This way the packet can be redirected to a specific task inside a satellite's board. 
This protocol can use various typical embedded networks such as CAN, I2C, SPI or even UART.

CSP provides a documentation to set up a CSP client and exchange packets. This documentation can be found in `/libcsp <https://github.com/libcsp/libcsp>`_

.. figure:: /_static/CSP_protocol.svg
      :scale: 110 %
      :align: center
      :alt: CSP packet

The above figure describes the composition of the CSP packet, and it consists of two parts, the header and the data field. 
The 32 bit header contains source and destination addresses, source and destination ports and basic means for authentication(HMAC), 
encryption(XTEA), UDP/RDP-like connections, and checksums(CRC). The header part is used to identify the sender and the recipient of the task or user. 
The data field is the data to send.

.. _RP:

**Radio Packet**:

The data send to the Robusta satellite and receive from the satellite is a CSP packet, with the length of the data to send included in the data field, 
and it's referred as radio packet. Information about the radio packet is given below.

.. figure:: /_static/radio_packet.svg
      :scale: 110 %
      :align: center
      :alt: Radio packet

In the figure above we can see the composition of a radio packet. The Data field must include as the first two byte the length of the data to send, 
then comes the data to send. The field 'Data to send' will be the HAM radio packet to be send, but for this the field need to 
be configured in a specific manner, look into the :ref:`HAM radio packet<HAMP>` section. Information and value about the CSP header fields are given below.

.. list-table:: CSP header
   :align: center
   :header-rows: 1
   :widths: 10 10 60

   *  - Field name
      - Description
      - Value
   *  - Priority
      - The priority of the packet
      - 0x02
   *  - Source address
      - The address of the sender
      - 0x1D
   *  - Destination address
      - The address of the HAM radio messaging system task
      - 0x09
   *  - Destination port
      - The port number of the HAM radio messaging system task
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
The HAM radio packet is basically a :ref:`radio packet <RP>` where the 'data to send' field is configured in a specific manner.
The HAM radio messaging system have two different command type and seven different command that can be used.
Command types are divided into user and administrator commands. The user type commands are the commands that can be used from radio amateur users,
the admin type commands are the private commands that can be used only from CSUM operators. Commands itself are actions that are requested to be executed.
More information about command types and commands can be found in the tables below.

.. list-table:: Command types
   :align: center
   :header-rows: 1
   :widths: 60 80

   *  - Command Type
      - The byte that identifies the command type
   *  - User command
      - 'u'
   *  - Admin command
      - 'a'

.. list-table:: Command types and commands
   :align: center
   :header-rows: 1
   :widths: 10 10 60

   *  - Command Type
      - Command
      - The byte that identifies the command
   *  - User command
      - Send Message
      - 's'
   *  - User command
      - Ask Message
      - 'a'
   *  - User command
      - Get Saved Messages ID
      - 'c'
   *  - Admin command
      - Change password
      - 'p'
   *  - Admin command
      - Delete all messages
      - 'd'
   *  - Admin command
      - Change sent message delay
      - 't'
   *  - Admin command
      - Change not sent message delay
      - 'n'

HAM radio packets have different configurations for different command and command type, and those configurations can be seen in the section below.

**HAM Radio User Packets**:

.. figure:: /_static/callsign.svg
      :scale: 120 %
      :align: center
      :alt: Call sign

Call signs are already used to identify a HAM Radio station or operator. Based on this the HAM Radio Messaging System also use call sign to identify users.
In the figure above we can see a call sign, it consist of two parts 'Prefix' and 'Serial letters'.

.. _SCMD:

* Send Message Command

.. figure:: /_static/ham_sending_message.svg
      :scale: 120 %
      :align: center
      :alt: Send message command configuration


This HAM radio packet configuration shown above is used to send a message to another user.
The 'HAM CRC' is a value used to check if the message is changed since it was created,
it is automatically calculated from the :ref:`encryption software <ENCR>`.
The 'Command Type' must be 'u' because its a user command and 'Command' must be set to 's'.
The 'Sender Call Sign' is the call sign of the user who is sending the message,
the 'Recipient Call Sign' is the call sign of the user supposed to receive the message and the 'Message' part is the message to transmit.

When the user sends this packet and the satellite receives it, the HAM radio messaging system task will check the HAM CRC,command type, 
command, message length, how many messages has saved the sender of the package and the total number of stored messages, 
then it will store the message. These constraints have predefined values and can be viewed in the :ref:`Constraints and Constants section <CONS>`.

* Ask Message Command

.. figure:: /_static/ham_asking_message.svg
      :scale: 120 %
      :align: center
      :alt: Ask message command configuration

This HAM radio packet configuration shown above is used to ask the satellite if there is a saved message for the requesting user.
The 'Command Type' must be 'u' because its a user command and The 'Command' must be set to 'a'.
The 'Sender Call Sign' is the call sign for which the satellite will search a stored message.

When the user sends this packet and the satellite receives it, the HAM radio messaging system task will check the validity, create a packet containing the
message and send it to the :ref:`Radio TX Queue <ham-queues-definition-table>` if there is a message for the requested call sign (therefore the requesting user).
Then the Radio Interface Task will handle the transmission of this packet to the user.

.. figure:: /_static/ham_message_sat.svg
      :scale: 120 %
      :align: center
      :alt: Ask message command response packet configuration

This HAM radio packet configuration shown above is used when the message is sent to a user from the satellite.
It is basically what you will get when yo have sent the command 'ask message' to the satellite and the satellite found a message matching your call sign.
After the reception and validation of the HAM radio packet the HAM radio messaging system task will additionally add a 'Message Tag' and 'Timestamp'
to the packet before storing it. The 'Timestamp' is the number of seconds that have elapsed since January 1, 1970 (midnight UTC/GMT), its providing 
information about when the message was sent. The 'Message tag' is used for checking the state of stored message. More details about the 'Message Tag' 
can be found in the table below.

The encrypted part of the packet is encrypted from the HAM radio messaging system task before it was sent. So user must decrypt this part with the help 
of the :ref:`data diffusion platform <DDP>` in order to read the message it contain.

.. list-table:: HAM radio Packet tag
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

* Get Saved Messages ID Command

.. figure:: /_static/ham_get_id.svg
      :scale: 120 %
      :align: center
      :alt: Get messages id command packet configuration

This HAM radio packet configuration shown above is used to get the timestamp, the sender and recipient call sign and the tag of all saved messages in satellite.
The 'Command Type' must be 'u' because its a user command and the 'Command' must be set to 'c'.

When the user send this packet and the satellite receives it, the HAM radio messaging system task will check the validity, check if there are saved messages,  
create a packet containing the identifiers of those saved messages and send it to the :ref:`radio TX queue <ham-queues-definition-table>`. 
Then the radio interface task will handle the transmission of this packet to the user.

.. figure:: /_static/ham_rep.svg
      :scale: 120 %
      :align: center
      :alt: Get messages id command response packet configuration

The HAM radio packet configuration shown above is what you will get when you have sent the command 'Get Saved Messages ID' to the satellite 
and if there is saved messages in the satellite.

**HAM Radio Admin Packets**:

The HAM radio admin packets use password for security purpose. The HAM radio messaging system has a default password, but this default password 
can be changed with the help of the 'change password' command which will be explained later (The password must be 6 bytes).

* Delete All Saved Messages Command
  
.. figure:: /_static/ham_del_cmd.svg
      :scale: 120 %
      :align: center
      :alt: Delete messages command packet configuration

This HAM radio packet configuration shown above is used to delete all the messages saved in the satellite. 
The 'Command Type' must be 'a' because its a admin command and the 'Command' must be set to 'd'.
When the satellite receive this packet it will check if the password is correct and delete all the saved message.

* Change Sent Message Delay Command

.. figure:: /_static/ham_delay_cmd2.svg
      :scale: 120 %
      :align: center
      :alt: Change sent message delay command packet configuration

This HAM radio packet configuration shown above is used to change the delay time given before deleting the saved messages that have the sent tag. 
The 'Command Type' must be 'a' because its a admin command and the 'Command' must be set to 't'. The delay value field is limited to 3 bytes and work with string, so per example 
if you want to change the value with 20 seconds you should configure the delay value field with two separate bytes like '2' and '0'. The maximum value that can be sent is 999 seconds(16,65 minutes).
The HAM radio messaging system has a default value for the sent message delay and this value can see in the :ref:`Message Constraints and Constants Table <CONS>`.

When the admin send this packet and the satellite receives it, the HAM radio messaging system task will will check if the password is correct, 
check the length of value sent, change the delay value with the new one and save this new value in the :ref:`eeprom <EEP>`.

* Change Not Sent Message Delay Command

.. figure:: /_static/ham_delay_cmd.svg
      :scale: 120 %
      :align: center
      :alt: Change not sent message delay command packet configuration

This HAM radio packet configuration shown above is used to change the delay time given before deleting the saved messages that have the not sent tag. 
The 'Command Type' must be 'a' because its a admin command and the 'Command' must be set to 'n'. The delay value field is limited to 6 bytes and work with string, so per example 
if you want to change the value with 20 seconds you should configure the delay value field with two separate bytes like '2' and '0'. The maximum value that can be sent is 999999 seconds(11,57 days).
The HAM radio messaging system has a default and minimum value for the not sent message delay and this value can see in the :ref:`Message Constraints and Constants Table <CONS>`.

When the admin send this packet and the satellite receives it, the HAM radio messaging system task will check if the password is correct, 
check the length of value sent, change the delay value with the new one and save this new value in the :ref:`eeprom <EEP>`.

* Change Password Command

.. figure:: /_static/ham_pwd_cmd.svg
      :scale: 120 %
      :align: center
      :alt: Change password command packet configuration

This HAM radio packet configuration shown above is used to change the default password which is used from admin type commands. 
The 'Command Type' must be 'a' because its a admin command and the 'Command' must be set to 'p'.

When the admin send this packet and the satellite receives it, the HAM radio messaging system task will check if the password is correct, 
check if the new password and the confirmation password is equal, change the default password with the new one and save this new password in the :ref:`eeprom <EEP>`.

.. _ACK:

**HAM Radio ACK/NACK Packet**:

When data is transmitted between two systems, an acknowledgement (ACK) can be sent to confirm an action and a negative-acknowledgment (NACK) can 
be sent to report an error. Based on the situation the HAM radio messaging system task replies with a ACK/NACK packet to inform the GS/User.
For example if you send a HAM radio packet with 'Send Message' command and your packet is valid, the satellite will reply you with an ACK packet.
There are several different case which reply a ACK/NACK packet, those case can be seen in the :ref:`functional diagram <FD>`.

.. figure:: /_static/ham_ack.svg
      :scale: 110 %
      :align: center
      :alt: ACK/NACK packet Data field configuration

The HAM radio messaging system task also uses the :ref:`radio packet <RP>` with 2 bytes in the 'data to send' field to create ACK/NACK packets. 
In the figure above we can see the ACK/NACK packet. The first field, 'Type Code', is used to identify the type of the packet. The second field, 
'ACK/NACK packet message code', is used to identify the message that give more details about the ACK/NACK.
The HAM radio messaging system task will create a ACK/NACK packet based on the situation and send it to the Radio TX Queue. 
Then the radio interface task will handle the transmission of this packet to the user.
More information about ACK/NACK packets can be seen in the tables below.

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
   ACK     0x04                      The delay value for not sent messages is updated successfully
   ACK     0x05                      The delay value for sent messages is updated successfully
   ACK     0x06                      All saved messages are deleted
   ACK     0x07                      Admin password is changed successfully
   NACK    0x08                      Invalid command
   NACK    0x09                      Storable maximum message number has been reached
   NACK    0x0A                      Invalid HAM CRC
   NACK    0x0B                      No message for the given call sign
   NACK    0x0C                      Maximum length of the message exceeded
   NACK    0x0D                      Allowed maximum number of storable message for the person has been reached
   NACK    0x0E                      There are no saved messages at all
   NACK    0x0F                      The command type is invalid
   NACK    0x10                      The password is invalid
   NACK    0x11                      The password in the double confirmation is not the same as each other
   NACK    0x12                      The length of the delay value sent from user is to long
   NACK    0x13                      The delay value sent from user contain invalid character
   NACK    0x14                      The not sent message delay value sent from user is to small
   ==== ============================ ====================================================================

.. _EEP:

HAM Radio Messaging System Storage
-----------------------------------

Some of the important data/value sent from GS/User are saved in eeprom so that it is not lost during a TT&C reset or any other situation. Information about those saved data can be seen in the table below.

.. list-table:: Data saved in the eeprom
   :align: center
   :header-rows: 1

   *  - Saved data
      - Description
      - Eeprom Address
   *  - Ham radio packet with send message command
      - The HAM Radio packets sent containing a message
      - 1-20
   *  - Sent message delay value
      - The delay value sent for the packets that has the message sent tag
      - 22
   *  - Not sent message delay value
      - The delay value sent for the packets that has the message not sent tag
      - 23
   *  - Password
      - The password used in the HAM radio admin packets.
      - 21

.. _CONS:

HAM Radio Messaging System Constants And Constraints
----------------------------------------------------

The constraints and constants concerning HAM radio messages are listed in the table below.

.. list-table::
   :align: center
   :header-rows: 1
   :widths: 10 60

   *  -  Constants/Constraints
      -  Value
   *  - The maximum allowed length of the message (in bytes)
      - 20
   *  - The maximum number of storable messages in the satellite
      - 20
   *  - The maximum allowed number of storable message for a sender
      - 1
   *  - The default delay time given before deleting messages with the sent tag
      - 20 seconds
   *  - The minimum delay value that can be set for the sent messages
      - 0 seconds
   *  - The default delay time given before deleting messages with the not sent tag
      - 86400 seconds(24 hours)
   *  - The minimum delay value that can be set for the not sent messages
      - 43200 seconds(12 hours)

The characters available in the Ham radio messaging system are shown below.

.. figure:: /_static/ham_char.svg
      :name: char_table
      :width: 40%
      :align: center
      :alt: HAM radio messaging system available characters

      HAM radio messaging system available character

.. _ENCR:

HAM Radio Packet Encryption
------------------------------

The HAM radio encryption is used in order to ensure that packets are sent from the correct user and delivered to the correct user. 
Beside that the encryption also provide a security for the admin type commands.
Before sending, the :ref:`HAM radio packet <HAMP>` is pseudo-encrypted with a cipher algorithm and a HAM CRC is automatically calculated and 
added to be sure that the content is not changed since the creation.

After the reception of a HAM Radio packet the HAM radio messaging system task checks the CRC and the validity then decrypt and process the packet according to 
the command. The HAM radio messaging system task encrypt HAM radio packets that contain message before sending them to users. 
When users receive a HAM radio packet as the response of an 'ask message' command that contain the message user must decrypt the encrypted part of the 
packet to read the message correctly.

This encryption/decryption process is achieved with the help of the :ref:`data diffusion platform <DDP>`.

.. _DDP:

DDP(Data Diffusion Platform)
----------------------------
The DDP is used to send data to CSUM external partners. This data can be mission data or other types of data that needs to shared. 
We have also developed a part for the ROBUSTA 3A mission and the HAM Radio messaging system. With this, 
users will be able to create their encrypted :ref:`HAM radio packets <HAMP>` to send them or decrypt their 
received :ref:`HAM radio packets <HAMP>` to read the message they contain. A general view of the DDP can be seen in the image below.

`Link to access the Data Diffusion Platform <http://162.38.203.31/ROB3A/>`_

.. figure:: /_static/Ham_ddp.png
      :width: 75%
      :align: center
      :alt: HAM radio messaging system data diffusion platform

      HAM radio messaging system Data diffusion platform

Functional Diagram
---------------------

.. _FD:

.. figure:: /_static/HAMradio_task_diagram1.svg
      :name: diagram1
      :width: 75%
      :align: center
      :alt: HAM radio messaging system task Flow Diagram part 1

      HAM radio messaging system task flow diagram part 1

.. figure:: /_static/HAMradio_task_diagram2.svg
      :name: diagram2
      :width: 100%
      :align: center
      :alt: HAM radio messaging system task flow diagram part 2

      HAM radio messaging system task flow diagram part 2

.. figure:: /_static/HAMradio_task_diagram3.svg
      :name: diagram3
      :width: 100%
      :align: center
      :alt: HAM radio messaging system task Flow Diagram part 3

      HAM radio messaging system task flow diagram part 3
