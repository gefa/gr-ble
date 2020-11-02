#!/usr/bin/python3
#
#  ble-dump: SDR Bluetooth LE packet dumper
#
#  Copyright (C) 2016 Jan Wagner <mail@jwagner.eu>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#

from grc.gr_ble import gr_ble as gr_block
from optparse import OptionParser, OptionGroup
from gnuradio.eng_option import eng_option
from datetime import datetime, timedelta
from proto import *
import zmq
import socket
import time

# print(current Gnu Radio capture settings)
def print_settings(gr, opts):
  print('\n ble-dump:  SDR Bluetooth LE packet dumper')
  print('\nCapture settings:')
  print(' %-22s: %s Hz' % ('Base Frequency', '{:d}'.format(int(gr.get_ble_base_freq()))))
  print(' %-22s: %s Hz' % ('Sample rate', '{:d}'.format(int(gr.get_sample_rate()))))
  print(' %-22s: %s dB' % ('Squelch threshold', '{:d}'.format(int(gr.get_squelch_threshold()))))

  print('\nLow-pass filter:')
  print(' %-22s: %s Hz' % ('Cutoff frequency', '{:d}'.format(int(gr.get_cutoff_freq()))))
  print(' %-22s: %s Hz' % ('Transition width', '{:d}'.format(int(gr.get_transition_width()))))

  print('\nGMSK demodulation:')
  print(' %-22s: %s' % ('Samples per Symbol', '{:.4f}'.format(gr.get_gmsk_sps())))
  print(' %-22s: %s' % ('Gain Mu', '{:.4f}'.format(gr.get_gmsk_gain_mu())))
  print(' %-22s: %s' % ('Mu', '{:,}'.format(gr.get_gmsk_mu())))
  print(' %-22s: %s' % ('Omega Limit', '{:.4f}'.format(gr.get_gmsk_omega_limit())))

  print('\nBluetooth LE:')
  print(' %-22s: %s' % ('Scanning Channels', '{:s}'.format(opts.current_ble_channels.replace(',', ', '))))
  print(' %-22s: %ss' % ('Scanning Window', '{:.2f}'.format(opts.ble_scan_window)))
  print(' %-22s: %s' % ('Disable CRC check', '{0}'.format(opts.disable_crc)))
  print(' %-22s: %s' % ('Disable De-Whitening', '{0}'.format(opts.disable_dewhitening)))

  print('\n%-23s: %s\n' % ('PCAP output file', '{:s}'.format(opts.pcap_file)))

# Setup Gnu Radio with defined command line arguments
def init_args(gr, opts):
  gr.set_sample_rate(int(opts.sample_rate))
  gr.set_squelch_threshold(int(opts.squelch_threshold))
  gr.set_cutoff_freq(int(opts.cutoff_freq))
  gr.set_transition_width(int(opts.transition_width))
  gr.set_gmsk_sps(opts.samples_per_symbol)
  gr.set_gmsk_gain_mu(opts.gain_mu)
  gr.set_gmsk_mu(opts.mu)
  gr.set_gmsk_omega_limit(opts.omega_limit)
  gr.set_ble_channel(int(opts.scan_channels[0]))

# Initialize command line arguments
def init_opts(gr):
  parser = OptionParser(option_class=eng_option, usage="%prog: [opts]")

  # Capture
  capture = OptionGroup(parser, 'Capture settings')
  capture.add_option("-o", "--pcap_file", type="string", default='', help="PCAP output file or named pipe (FIFO)")
  capture.add_option("-m", "--min_buffer_size", type="int", default=65, help="Minimum buffer size [default=%default]")
  capture.add_option("-s", "--sample-rate", type="eng_float", default=gr.sample_rate, help="Sample rate [default=%default]")
  capture.add_option("-t", "--squelch_threshold", type="eng_float", default=gr.squelch_threshold, help="Squelch threshold (simple squelch) [default=%default]")

  # Low Pass filter
  filters = OptionGroup(parser, 'Low-pass filter:')
  filters.add_option("-C", "--cutoff_freq", type="eng_float", default=gr.cutoff_freq, help="Filter cutoff [default=%default]")
  filters.add_option("-T", "--transition_width", type="eng_float", default=gr.transition_width, help="Filter transition width [default=%default]")

  # GMSK demodulation
  gmsk = OptionGroup(parser, 'GMSK demodulation:')
  gmsk.add_option("-S", "--samples_per_symbol", type="eng_float", default=gr.gmsk_sps, help="Samples per symbol [default=%default]")
  gmsk.add_option("-G", "--gain_mu", type="eng_float", default=gr.gmsk_gain_mu, help="Gain mu [default=%default]")
  gmsk.add_option("-M", "--mu", type="eng_float", default=gr.gmsk_mu, help="Mu [default=%default]")
  gmsk.add_option("-O", "--omega_limit", type="eng_float", default=gr.gmsk_omega_limit, help="Omega limit [default=%default]")

  # Bluetooth L
  ble= OptionGroup(parser, 'Bluetooth LE:')
  ble.add_option("-c", "--current_ble_channels", type="string", default='37,38,39', help="BLE channels to scan [default=%default]")
  ble.add_option("-w", "--ble_scan_window", type="eng_float", default=10.24, help="BLE scan window [default=%default]")
  ble.add_option("-x", "--disable_crc", action="store_true", default=False, help="Disable CRC verification [default=%default]")
  ble.add_option("-y", "--disable_dewhitening", action="store_true", default=False, help="Disable De-Whitening [default=%default]")

  parser.add_option_group(capture)
  parser.add_option_group(filters)
  parser.add_option_group(gmsk)
  parser.add_option_group(ble)
  return parser.parse_args()

# 24-bit CRC function
def crc(data, length, init=0x555555):
  ret = [(init >> 16) & 0xff, (init >> 8) & 0xff, init & 0xff]

  for d in data[:length]:
    for v in range(8):
      t = (ret[0] >> 7) & 1;

      ret[0] <<= 1
      if ret[1] & 0x80:
        ret[0] |= 1

      ret[1] <<= 1
      if ret[2] & 0x80:
        ret[1] |= 1

      ret[2] <<= 1

      if d & 1 != t:
        ret[2] ^= 0x5b
        ret[1] ^= 0x06

      d >>= 1

  ret[0] = swap_bits((ret[0] & 0xFF))
  ret[1] = swap_bits((ret[1] & 0xFF))
  ret[2] = swap_bits((ret[2] & 0xFF))

  return ret

def bin_string_to_list(packet_bin):
  # convert to list
  packet_list = []
  [packet_list.append(byte) for byte in packet_bin]
  return packet_list

def list_to_bin_string(packet_list):
  # convert back to bin string
  packet_bin = b''
  for byte in packet_list:
    packet_bin = packet_bin + bytes([byte])
  return packet_bin

#packet = b'\x55\x55\x55\x6b\x7d\x91\x71\xf1\x13\x15\xf2\x07\xd6\xbb\x58\xee\x0c\xe8\x1a\x79\x24\x89\xf1\xe4\xd1\x1b\x0f\x33\x48\x5e\x29\x77\xbb\xda\x0e\x65\x6b\x58\x8e\xc5\x29\x89\x8c\xf0\xdc\x32\x36\xba\x32\x20'
#packet_b = b'\x00\x00\x00\x00\x00\x00\x00\x00\xd6\xbe\x89\x8e\x02\x1a\xff\xee\xdd\xcc\xbb\xaa\x02\x01\x06\x10\x08\x53\x69\x6c\x61\x62\x73\x20\x52\x41\x49\x4c\x54\x45\x53\x54\x6d\xed\xe6'
padding_access_address = b'\x00\x00\x00\x00\x00\x00\x00\x00\xd6\xbe\x89\x8e'
packet_header = b'\x00' # ADV_IND
#packet_len_byte = b'\x1a'
address = b'\xff\xee\xdd\xcc\xbb\xaa'
flags = b'\x02\x01\x06'
#length= '\x10' # find out below
device_type = b'\x08'
#message = b'\x53\x69\x6c\x61\x62\x73\x20\x52\x41\x49\x4c\x54\x45\x53\x54'
message = 'HelloNislab!'.encode('ascii')
length = bytes([len(message)+1]) # + 1 for device_type byte

packet_len_byte = len(address + flags + length + device_type + message)
print(packet_len_byte)
payload = packet_header + bytes([packet_len_byte]) + address + flags + length + device_type + message
payload_len = len(payload)

crc_bytes = crc(bin_string_to_list(payload),payload_len)
#print("CRC##########")
#print(crc_bytes)
packet = padding_access_address + payload + list_to_bin_string(crc_bytes)
print(packet)

def send_packet(s: socket.socket, ip: str, port: int):
    #print(f'Sending packet {packet} to ip {ip} and port {port}')
    return s.sendto(packet, (ip, port))

if __name__ == '__main__':
  MIN_BUFFER_LEN = 65

  # Initialize Gnu Radio
  gr_block = gr_block()
  gr_block.start()

  # Initialize command line arguments
  (opts, args) = init_opts(gr_block)

  if not opts.pcap_file:
    print('\nerror: please specify pcap output file (-p)')
    exit(1)

  # Verify BLE channels argument
  if ',' not in opts.current_ble_channels:
    opts.current_ble_channels += ','

  # Prepare BLE channels argument
  opts.scan_channels = [int(x) for x in opts.current_ble_channels.split(',')]

  # Set Gnu Radio opts
  init_args(gr_block, opts)

  # Print capture settings
  print_settings(gr_block, opts)

  # Open PCAP file descriptor
  pcap_fd = open_pcap(opts.pcap_file)

  current_hop = 1
  hopping_time = datetime.now() + timedelta(seconds=opts.ble_scan_window)

  # Set initial BLE channel
  current_ble_chan = opts.scan_channels[0]
  gr_block.set_ble_channel(BLE_CHANS[current_ble_chan])

  # Prepare Gnu Radio receive buffers
  gr_buffer = ''
  lost_data = ''
  socket_str = "tcp://127.0.0.1:5557"
  context = zmq.Context()
  results_receiver = context.socket(zmq.PULL)
  results_receiver.connect(socket_str)
  print('Capturing on BLE channel [ {:d} ] @ {:d} MHz'.format(current_ble_chan, int(gr_block.get_freq() / 1000000)))
  
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  ip = "127.0.0.1"
  port = 52001
  millis = int(round(time.time() * 1000))
  # for i in range(5):
  #   send_packet(s, ip, port)
  #   sleep(0.2)

  try:
    while True:
      if int(round(time.time() * 1000)) < millis+10:
        pass
      else:
        # send every 50ms, 'cause sending every loop is too fast
        millis = int(round(time.time() * 1000))
        send_packet(s, ip, port)
      # Move to the next BLE scanning channel
      if datetime.now() >= hopping_time:
        current_ble_chan = opts.scan_channels[current_hop % len(opts.scan_channels)]
        gr_block.set_ble_channel(BLE_CHANS[current_ble_chan])
        hopping_time = datetime.now() + timedelta(seconds=opts.ble_scan_window)
        current_hop +=1
        print('Switching to BLE channel [ {:d} ] @ {:d} MHz'.format(current_ble_chan, int(gr_block.get_freq() / 1000000)))

      # Fetch data from Gnu Radio message queue
      gr_buffer +=  results_receiver.recv().decode('latin1')
      if len(gr_buffer) > opts.min_buffer_size:
        # Prepend lost data
        if len(lost_data) > 0:
          gr_buffer = ''.join(str(x) for x in lost_data) + gr_buffer
          lost_data = ''

        # Search for BLE_PREAMBLE in received data
        for pos in [position for position, byte, in enumerate(gr_buffer) if byte == BLE_PREAMBLE]:
          pos += BLE_PREAMBLE_LEN

          # Check enough data is available for parsing the BLE Access Address
          if len(gr_buffer[pos:]) < (BLE_ADDR_LEN + BLE_PDU_HDR_LEN):
            continue

          # Extract BLE Access Address
          ble_access_address = unpack('I', bytes(gr_buffer[pos:pos + BLE_ADDR_LEN], 'latin1'))[0]
          pos += BLE_ADDR_LEN

          # Dewhitening received BLE Header
          if opts.disable_dewhitening == False:
            ble_header = dewhitening(gr_buffer[pos:pos + BLE_PDU_HDR_LEN], current_ble_chan)
          else:
            ble_header = gr_buffer[pos:pos + BLE_PDU_HDR_LEN]

          # Check BLE PDU type
          ble_pdu_type = ble_header[0] & 0x0f
          if ble_pdu_type not in BLE_PDU_TYPE.values():
             continue

          if ble_access_address == BLE_ACCESS_ADDR:
            # Extract BLE Length
            ble_len = ble_header[1] & 0x3f
          else:
            ble_llid = ble_header[0] & 0x3
            if ble_llid == 0:
              continue

            # Extract BLE Length
            ble_len = ble_header[1] & 0x1f

          # Dewhitening BLE packet
          if opts.disable_dewhitening == False:
            import struct
            #print(type(gr_buffer[0]))
            arr=gr_buffer[pos - BLE_ADDR_LEN - BLE_PREAMBLE_LEN:pos + BLE_PDU_HDR_LEN + BLE_CRC_LEN + ble_len]
            print_later = []
            [ print_later.append(ord(x)) for x in arr]
            ble_data = dewhitening(gr_buffer[pos:pos + BLE_PDU_HDR_LEN + BLE_CRC_LEN + ble_len], current_ble_chan)
            print_later_dew = ble_data
            #[ print_later_dew.append(ord(x)) for x in ble_data]
            #print(ble_data)
          else:
            ble_data = gr_buffer[pos:pos + BLE_PDU_HDR_LEN + BLE_CRC_LEN + ble_len]

          # Verify BLE data length
          if len(ble_data) != (BLE_PDU_HDR_LEN + BLE_CRC_LEN + ble_len):
            lost_data = gr_buffer[pos - BLE_PREAMBLE_LEN - BLE_ADDR_LEN:pos + BLE_PREAMBLE_LEN + BLE_ADDR_LEN + BLE_PDU_HDR_LEN + BLE_CRC_LEN + ble_len]
            continue

          # Verify BLE packet checksum
          if opts.disable_crc == False:
            if ble_data[-3:] != crc(ble_data, BLE_PDU_HDR_LEN + ble_len):
              continue
            #else:
              #print("CRC ble_data:")
              #print(ble_data)
              #print("CRC ble_len:{}".format(BLE_PDU_HDR_LEN + ble_len))
              #print("CRC bytes")
              #print(ble_data[-3:])
          #print("before De-Whitening")
          #print("b'" + ''.join('\\x{:02x}'.format(x) for x in print_later)+ "'")
          print("after De-Whitening")
          print(print_later_dew)
          #print("b'" + ''.join('\\x{:02x}'.format(x) for x in print_later_dew)+ "'")
          print(list_to_bin_string(print_later_dew))
          # Write BLE packet to PCAP file descriptor
          write_pcap(pcap_fd, current_ble_chan, ble_access_address, ble_data)

        gr_buffer = ''

  except KeyboardInterrupt:
    pass

pcap_fd.close()
gr_block.stop()
gr_block.wait()
