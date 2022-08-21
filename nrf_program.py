#######################################################
#     Spiros Daskalakis                               #
#     last Revision: 12/08/2022                       #
#     Python Version:  3.7                            #
#     Email: daskalakispiros@gmail.com                #
#######################################################

import time

# Receiver Firmware:
# https://docs.ruuvi.com/ruuvi-gateway-firmware/gw-nrf52-firmware/gw-nrf52811-uart-communication

# Defines:
STX = 0xCA
DELIMITER = 0x2C
ETX = 0x0A
RB_BLE_MANUFACTURER_ID = 0x0499  # or 1177 in decimal

# Field Lengths
MAC_ADDRESS_LEN = 6
RSSI_LEN = 1
STX_LEN = 1
LEN_LEN = 1
CMD_LEN = 1
DELIMITER_LEN = 1
CRC_LEN = 2
ETX_LEN = 1

# Commands
RE_CA_UART_SET_FLTR_TAGS = 5  # Set filter tags.
RE_CA_UART_SET_FLTR_ID = 6  # Set manufacturer ID filter.
RE_CA_UART_SET_CODED_PHY = 7  # Set coded PHY.
RE_CA_UART_SET_SCAN_1MB_PHY = 8  # Set scan 1MBbit/PHY.
RE_CA_UART_SET_EXT_PAYLOAD = 9  # Set extended payload.
RE_CA_UART_SET_CH_37 = 10  # Set channel 37.
RE_CA_UART_SET_CH_38 = 11  # Set channel 38.
RE_CA_UART_SET_CH_39 = 12  # Set channel 39.
RE_CA_UART_SET_ALL = 15  # Set all config.
RE_CA_UART_ADV_RPRT = 16  # Advertisement report. ACK no need.
RE_CA_UART_DEVICE_ID = 17  # Send device id. ACK no need.
RE_CA_UART_GET_DEVICE_ID = 24  # Get device id. Expect RE_CA_UART_DEVICE_ID.
RE_CA_UART_GET_ALL = 25  # Get all config.
RE_CA_UART_ACK = 32  # ACK

# # Tag Settings
# SET_FLTR_TAGS = 1
# SET_CODED_PHY = 0
# SET_SCAN_1MB_PHY = 1  # for RI_RADIO_BLE_1MBPS YES
# SET_EXT_PAYLOAD = 1  # for RI_RADIO_BLE_2MBPS YES
# SET_CH_37 = 1
# SET_CH_38 = 1
# SET_CH_39 = 1


def cal_crc16(data: bytearray, offset, length):
    # Online Caltulator: https://www.lddgo.net/en/encrypt/crc
    # Theory: https://en.wikipedia.org/wiki/Cyclic_redundancy_check

    # CRC is CRC-16-CCITT-FALSE
    # Polynomial Formula: x16+x12+x5+1
    # Polynomial: 1021
    if data is None or offset < 0 or offset > len(data) - 1 and offset + length > len(data):
        return 0
    crc = 0xFFFF
    for i in range(0, length):
        crc ^= data[offset + i] << 8
        for j in range(0, 8):
            if (crc & 0x8000) > 0:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
    return crc & 0xFFFF


def check_crc16(data: bytearray, crc: bytearray):
    cal_crc = cal_crc16(data, 0, len(data))
    crc1_str = str(hex(cal_crc))[4:]
    crc1_int = int(crc1_str, 16)
    crc2_str = str(hex(cal_crc))[2:4]
    crc2_int = int(crc2_str, 16)
    array_crc = bytearray()
    array_crc.append(crc1_int)
    array_crc.append(crc2_int)
    array_crc_int = int.from_bytes(array_crc, "big")
    crc_int = int.from_bytes(crc, "big")
    if hex(crc_int) == hex(array_crc_int):
        print('Check_crc16: CORRECT')
        return 1
    else:
        print('Check_crc16: WRONG')
        return 0


def read_command(my_uart):
    print('---------Read COMMAND---------------')
    # 1 byte for STX (ca)
    # 1 byte for LEN (number)
    # 1 byte for CMD
    bytes_to_read = STX_LEN + LEN_LEN + CMD_LEN
    myBytes = my_uart.read(bytes_to_read)
    LEN_int = int(myBytes[1])
    CMD = myBytes[2]
    # ---->RE_CA_UART_ACK for set command
    # or
    # ---->RE_CA_UART_DEVICE_ID for get command
    # 1 byte for Command
    # 1 byte for DELIMITER
    # 1 byte for Command
    # 1 byte for DELIMITER
    # 2 bytes for CRC16
    # 1 byte for ETX

    bytes_to_read_2 = LEN_int + CRC_LEN + ETX_LEN
    myBytes2 = my_uart.read(bytes_to_read_2)
    packet_crc_check = myBytes[STX_LEN: STX_LEN + LEN_LEN + CMD_LEN] + myBytes2[0: LEN_int]
    mycrc = myBytes2[LEN_int:LEN_int + CRC_LEN]
    check_crc16(packet_crc_check, mycrc)

    if CMD == RE_CA_UART_ACK:
        print('READ COMMAND: RE_CA_UART_ACK')

        if int(LEN_int) != 0:
            for i in range(0, int(LEN_int), 2):
                command = myBytes2[i]
                # print('receiver_Command:', hex(command))
                delimiter = myBytes2[1 + i]
                # print('receiver_Delimiter:', hex(delimiter))
        return 1

    elif CMD == RE_CA_UART_DEVICE_ID:
        ID_bytes = bytearray()
        Addr_bytes = bytearray()
        print('CMD: RE_CA_UART_DEVICE_ID', CMD)
        adr_flag = 0
        if int(LEN_int) != 0:
            for i in range(0, int(LEN_int - 1)):
                command = myBytes2[i]
                # print('receiver_Command:', hex(command))
                if myBytes2[i] == 0x2c:
                    adr_flag = 1
                    i = i + 1
                if adr_flag == 0:
                    ID_bytes.append(myBytes2[i])
                elif adr_flag == 1:
                    Addr_bytes.append(myBytes2[i])
        return ID_bytes.hex(), Addr_bytes.hex()

    elif CMD == RE_CA_UART_GET_ALL:
        print('READ COMMAND: RE_CA_UART_GET_ALL', CMD)
        return 1
    else:
        print('READ SOMETHING WRONG')
        return 0


def get_device_id(my_uart):
    print('---------GET BLE DEVICE ID------------------')
    mycmd = RE_CA_UART_GET_DEVICE_ID
    packet = create_packet(mycmd)
    get_device_id_test = b"\xca\x00\x18\x36\x8E\x0a"
    my_uart.write(packet)
    devID, dev_addr = read_command(my_uart)
    return devID, dev_addr


def twos_complement(val, nbits):
    """Compute the 2's complement of int value val"""
    if val < 0:
        val = (1 << nbits) + val
    else:
        if (val & (1 << (nbits - 1))) != 0:
            # If sign bit is set.
            # compute negative value.
            val = val - (1 << nbits)
    return val


def set_one_command(my_uart, cmd, state=1):
    print('---------SET COMMAND------------------')
    packet = create_packet(cmd, state)
    test_RE_CA_UART_SET_CH_37 = b"\xca\x02\x0a\x01\x2c\xb6\x78\x0a"
    my_uart.write(packet)
    read_command(my_uart)


def init_receiver(my_uart, filt_tags=1, coded_phy=0, scan_1bmps_phy=1, ext_payload=1, ch_37=1, ch_38=1, ch_39=1):
    print('---------INIT RECEIVER------------------')
    cmd = RE_CA_UART_SET_ALL
    packet = create_packet(cmd, filt_tags=filt_tags, coded_phy=coded_phy, scan_1bmps_phy=scan_1bmps_phy, ext_payload=ext_payload, ch_37=ch_37, ch_38=ch_38, ch_39=ch_39)
    my_uart.write(packet)
    read_command(my_uart)


def scan(my_uart, duration_min=2):
    t_end = time.time() + 60 * duration_min
    while time.time() < t_end:
        serial_line = my_uart.readline()

        print('READ LINE:', serial_line)  # If using Python 2.x use: print serial_line
        # Do some other work on the data
        LEN_int = int(serial_line[1])
        CMD = serial_line[2]
        packet_crc_check = serial_line[STX_LEN: (STX_LEN + LEN_LEN + CMD_LEN) + LEN_int]
        mycrc = serial_line[(STX_LEN + LEN_LEN + CMD_LEN) + LEN_int: (STX_LEN + LEN_LEN + CMD_LEN) + LEN_int + CRC_LEN]
        check_crc16(packet_crc_check, mycrc)

        if CMD == RE_CA_UART_GET_ALL:
            print('READ COMMAND: RE_CA_UART_GET_ALL')
        elif CMD == RE_CA_UART_ADV_RPRT:
            print('REPORT PAYLOAD')
            # for i in range(0, len(serial_line)):
            #     my_byte = serial_line[i]
            #     print('Byte:', hex(my_byte))

            MAC_address = serial_line[(STX_LEN + LEN_LEN + CMD_LEN): (STX_LEN + LEN_LEN + CMD_LEN + MAC_ADDRESS_LEN)]
            Advertisement_length = LEN_int - MAC_ADDRESS_LEN - RSSI_LEN - 3 * DELIMITER_LEN
            Advertisement = serial_line[(STX_LEN + LEN_LEN + CMD_LEN + MAC_ADDRESS_LEN + DELIMITER_LEN): (
                    STX_LEN + LEN_LEN + CMD_LEN + + MAC_ADDRESS_LEN + DELIMITER_LEN + Advertisement_length)]

            RSSI_in_dB = serial_line[
                STX_LEN + LEN_LEN + CMD_LEN + MAC_ADDRESS_LEN + DELIMITER_LEN + Advertisement_length + DELIMITER_LEN]
            print('MAC ADR (HEX):', MAC_address.hex())
            print('ADVERTISMENT PACKET:', Advertisement)
            print('ADVERTISMENT LEN (bytes):', Advertisement_length)
            print('RSSI (dBm):', twos_complement(RSSI_in_dB, 8))
        else:
            print('READ SOMETHING WRONG')


def create_packet(CMD, State=1, filt_tags=1, coded_phy=0, scan_1bmps_phy=1, ext_payload=1, ch_37=1, ch_38=1, ch_39=1):
    data_packet = bytearray()
    crc_packet = bytearray()
    data_packet.append(STX)
    if CMD == RE_CA_UART_SET_CH_37 or CMD == RE_CA_UART_SET_CH_38 or CMD == RE_CA_UART_SET_CH_39 or CMD == RE_CA_UART_SET_SCAN_1MB_PHY or CMD == RE_CA_UART_SET_CODED_PHY:
        LEN = 0x02
        crc_packet.append(LEN)
        crc_packet.append(CMD)
        crc_packet.append(State)
        crc_packet.append(DELIMITER)
        crc_int = cal_crc16(crc_packet, 0, len(crc_packet))
        # flip the bytes of CRC
        crc1_str = str(hex(crc_int))[4:]
        crc1_int = int(crc1_str, 16)
        crc2_str = str(hex(crc_int))[2:4]
        crc2_int = int(crc2_str, 16)

        data_packet.append(LEN)
        data_packet.append(CMD)
        data_packet.append(State)
        data_packet.append(DELIMITER)
        data_packet.append(crc1_int)
        data_packet.append(crc2_int)

    if CMD == RE_CA_UART_GET_DEVICE_ID:
        LEN = 0x00
        crc_packet.append(LEN)
        crc_packet.append(CMD)
        crc_int = cal_crc16(crc_packet, 0, len(crc_packet))
        # flip the bytes of CRC
        crc1_str = str(hex(crc_int))[4:]
        crc1_int = int(crc1_str, 16)
        crc2_str = str(hex(crc_int))[2:4]
        crc2_int = int(crc2_str, 16)

        data_packet.append(LEN)
        data_packet.append(CMD)
        data_packet.append(crc1_int)
        data_packet.append(crc2_int)

    if CMD == RE_CA_UART_SET_ALL:
        # split to two bytes
        comm1_RE_CA_UART_SET_FLTR_ID_1, comm1_RE_CA_UART_SET_FLTR_ID_2 = (RB_BLE_MANUFACTURER_ID & 0xFFFF).to_bytes(2,
                                                                                                                    'big')
        command_2 = filt_tags << 0 | coded_phy << 1 | scan_1bmps_phy << 2 | ext_payload << 3 | ch_37 << 4 | ch_38 << 5 | ch_39 << 6

        LEN = 2 + 3

        crc_packet.append(LEN)
        crc_packet.append(CMD)
        crc_packet.append(comm1_RE_CA_UART_SET_FLTR_ID_1)
        crc_packet.append(comm1_RE_CA_UART_SET_FLTR_ID_2)
        crc_packet.append(DELIMITER)
        crc_packet.append(command_2)
        crc_packet.append(DELIMITER)
        # Caltulate CRC
        crc_int = cal_crc16(crc_packet, 0, len(crc_packet))
        crc1_str = str(hex(crc_int))[4:]
        crc1_int = int(crc1_str, 16)
        crc2_str = str(hex(crc_int))[2:4]
        crc2_int = int(crc2_str, 16)

        data_packet.append(LEN)
        data_packet.append(CMD)
        # len start
        data_packet.append(comm1_RE_CA_UART_SET_FLTR_ID_1)
        data_packet.append(comm1_RE_CA_UART_SET_FLTR_ID_2)
        data_packet.append(DELIMITER)
        data_packet.append(command_2)
        data_packet.append(DELIMITER)
        # len end
        data_packet.append(crc1_int)
        data_packet.append(crc2_int)
    data_packet.append(ETX)
    return data_packet
