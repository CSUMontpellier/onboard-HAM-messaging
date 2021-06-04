TT&C Subsystem
==============

The TTC module stands for Telemetry, Tracking and Command. In the scope of this documentation, the TTC is the system (hardware and software) that enables an UHF link between the spacecraft (SAT) and a Ground Station (GS). This link will enable the Mission Control Center (MCC) to bidirectionally communicate with the satellite, receiving telemetry data about the current satellite condition, logs about previous events and send commands to the satellite to perform actions. 

The TTC is being designed to support the two different sallite platforms of CSUM: Robusta 1U and 3U. Both platforms have significant differences in terms of hardware (interface boards) and software (protocols). In order to accomodate all these differences between the two platforms and, at the same time, while keeping the hardware and software changes to a minimum level, the design is done trying to maximize modularity between the components.

General Specifications
----------------------

* Transmission Frequency: 435 - 437 MHz (TBC after Freq. request)
* Reception Frequency: 435 - 437 MHz (TBC after Freq. request)
* Supported Modulation: AFSK 1k2, GMSK 2k4 (GFSK with BT=0.5), GMSK 9k6 (GFSK with BT=0.5)
* Supported Radio Protocols: `AX25 <https://www.tapr.org/pdf/AX25.2.2.pdf>`_, `CSP <https://bytebucket.org/bbruner0/albertasat-on-board-computer/wiki/1.%20Resources/1.1.%20DataSheets/CSP/GS-CSP-1.1.pdf?rev=316ebd49bed49fdbb1d74efdeab74430e7cc726a>`_
* Maximum Bit Error Rate on reception: 10E-5
* Max TX output power (delivered to antenna): 33 dBm (~2 W)
* Satellite Interface: `CAN Bus <https://en.wikipedia.org/wiki/CAN_bus>`_
* Operational Temperature Range: -10 to 50°C
* Supply Voltage: 6V (Transceiver) and 5V (Power Amplifier)
* RF Interface: MMCX connectors
* Power consumption: Idle: 0.5 W, RX: <1 W, TX: 6 W