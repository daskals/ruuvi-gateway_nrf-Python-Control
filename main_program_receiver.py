#######################################################
#     Spiros Daskalakis                               #
#     last Revision: 21/08/2022                       #
#     Python Version:  3.7                            #
#     Email: daskalakispiros@gmail.com                #
#######################################################

import serial
import serial.tools.list_ports as port_list
import nrf_program
import sys


ports = list(port_list.comports())
for p in ports:
    if 'JLink' in p.description:
        jlink_serial = p.name

if jlink_serial:
    print("JLink UART Port Found!")
else:
    print("JLink UART Port <<Not>> found!")
    sys.exit()

# jlink_serial='COM9'
print('Selected Port:', jlink_serial)
ser = serial.Serial(jlink_serial)  # open serial port
ser.baudrate = 115200
ser.timeout = None

ID_bytes, Addr_bytes = nrf_program.get_device_id(ser)
print('NRF RECEIVER ID:', ID_bytes)
print('NRF RECEIVER Address:', Addr_bytes)

# Program the
nrf_program.init_receiver(ser, filt_tags=1, coded_phy=0, scan_1bmps_phy=1, ext_payload=0, ch_37=1, ch_38=1, ch_39=1)
# Scan for two mins
nrf_program.scan(ser, duration_min=2)
ser.close()

    
