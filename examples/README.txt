ble_rx.py is based on ble_dump.py from https://github.com/drtyhlpr/ble_dump

grc/gr_ble.grc receive's based on ble_dump and transmit's based on scapy-radio

To loopback-test both ble transmit and receive flowgraph run:
./ble_trx.py -o /tmp/dump.pcap

View packet capture after:
wireshark /tmp/dump.pcap &
