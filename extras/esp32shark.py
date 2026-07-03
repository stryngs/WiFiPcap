#!/usr/bin/env python

'''
  Copyright (C) 2023 - M Hightower

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
'''

'''
  This script does not create a pcap file. That task is left to Wireshark.
  This script connects the ESP32 using USB CDC to stdin of Wireshark, after
  setting ESP32's filter, channel, and time options.

  References:
    https://pyserial.readthedocs.io/en/latest/pyserial_api.html
    Wireshark https://wiki.wireshark.org/CaptureSetup/Pipes.md
    https://github.com/RIOT-OS/RIOT/blob/master/examples/sniffer/tools/sniffer.py
'''

import traceback
import sys
import argparse
import textwrap
import locale

import serial
import io
import os
import subprocess
import shlex
import signal
import platform
import time
import re
# https://stackoverflow.com/a/52809180
import serial.tools.list_ports

# Update Wireshark path as needed
wireshark_path='wireshark'
wireshark_path_win32=r'C:\Program Files\Wireshark\Wireshark.exe'

serialport = ""
bpsRate = 9216000
# bpsRate = 115200
esp32_name = "WiFiPcap"
docs_url = f"https://github.com/mhightower83/{esp32_name}/wiki"

# Regional values - The WiFiPcap is restricted by CONFIG_WIFIPCAP_CHANNEL_MAX in KConfig.h
# max_channel = 14
# max_channel = 13    # Europe
# https://en.wikipedia.org/wiki/List_of_WLAN_channels#endnote_B
# max_channel = 13    # North America - permitted with channels 12 & 13 at low power
max_channel = 11    # North America - more common range

# not using - keeping this for now
# retrieve *system* encoding, not the one used by python internally
if sys.version_info >= (3, 11):
    def get_encoding():
        return locale.getencoding()
else:
    def get_encoding():
        return locale.getdefaultlocale()[1]


def parseArgs():
    global docs_url
    name = os.path.basename(__file__)
    extra_txt = f'''\
       Defaults to starting capture with {esp32_name} using current WiFi Channel
       and set to GMT based on Host System's time. The captured stream is piped
       into Wireshark which begins capturing to a file.

       Use '--filter_...' options to reduce traffic through the USB CDC interface.
       Think of this as a stage 1 filter in front of Wireshark.
       When the filter option is omitted, the previous filter uploaded is used.

       Examples:

         {name} --filter_session --ch=11

         {name} -c6 --filter_mask "mgmt|data"

         {name} -c1 --filter_all

         {name} -c6 --filter "mgmt|data" --oui "00:DD:00" --multicast

       These mnemonics represent filter options offered by the ESP32 SDK.
       Join these mnemonics with '|' to construct a FILTER_MASK:

         all_mask    Keep all packets
         fcsfail     FCS failed packets, also includes bad packets

           Packets with type:
         mgmt          WIFI_PKT_MGMT
         ctrl          WIFI_PKT_CTRL
         data          WIFI_PKT_DATA
         misc          WIFI_PKT_MISC

         mpdu        MPDU a kind of WIFI_PKT_DATA
         ampdu       AMPDU a kind of WIFI_PKT_DATA

           WIFI_PKT_CTRL subtypes:
         wrapper       Control Wrapper
         bar           Block Ack Request
         ba            Block Ack
         pspoll        PS-Poll
         rts           RTS
         cts           CTS
         ack           ACK
         cfend         CF-END
         cfendack      CF-END+CF-ACK
         ctrl_mask     All WIFI_PKT_CTRL subtypes

           Custom - not in the ESP32 SDK
         session    Uses logic in callback function to select packets related
                    to AP connections
         fcslen     Experimental, FCS Length include in packet length

         0x10000    Hex constant are also supported

       more help at {docs_url}
       '''
    parser = argparse.ArgumentParser(
        description=f'Pipes {esp32_name} into Wireshark',
        formatter_class=argparse.RawDescriptionHelpFormatter,
              epilog=textwrap.dedent(extra_txt))
    parser.add_argument('--channel','-c', '--ch', type=int, choices=range(1, max_channel+1), required=False, default=None, help='Select/Change WiFi Channel')
    parser.add_argument('--no_time_sync', '-n', dest='time_sync', action='store_false', required=False, default=True, help=f'No time sync between Host and {esp32_name}.')
    parser.add_argument('--port', '-p', required=False, default=None, help=f'Full device path for USB CDC device connected to {esp32_name}.')
    parser.add_argument('--zc', dest='channel', type=int, choices=range(1, 15), required=False, default=None, help=argparse.SUPPRESS)   # debug
    parser.add_argument('--testing', '--test', '-t', action='store_true', default=None, help="Test run - It does everything but start Wireshark.")
    parser.add_argument('--gui', action='store_true', default=False, help='Start a small Tkinter control window instead of launching capture immediately.')


    group2 = parser.add_mutually_exclusive_group(required=False)
    group2.add_argument('--unicast', '-u', '--mac', required=False, default=None, help=f'unicast/MAC, 6 bytes of Source or Destination Address of interest expressed in hex and quoted, with "-" or ":" for byte separator')
    group2.add_argument('--oui', '-o', required=False, default=None, help=f'OUI, first 3 bytes of Source or Destination Address of interest in quotes with "-" or ":" separator')
    group2.add_argument('--no_addr', action='store_true', required=False, default=None, help=f'Clear Unicast/OUI filter option')

    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument('--multicast', '-m', nargs='?', action='store', required=False, default=None, const="01:00:00:00:00:00", help=f'Use with --unicast or --oui to capture multicast responses. First 3 or 6 bytes of a Multicast Address in hex and quoted, with "-" or ":" for byte separator. For a 3 byte value pad with zeros to 6 bytes.')
    group3.add_argument('--broadcast', '-b', action='store_true', required=False, default=None, help=f'Use with --unicast or --oui to capture broadcast responses.')


    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--filter_mask', '-f', '--filter', required=False, default=None, help='Specify WiFi filter mask. See example and mnemonic list below.')
    group.add_argument('--filter_all', '-a', action='store_true', default=None, help='Capture all packets possible, includes type control and bad packets')
    group.add_argument('--filter_good', '-g', action='store_true', default=None, help='Capture all good packets possible, includes type control')
    # This one should be the default
    group.add_argument('--filter_session', action='store_true', default=None, help='Capture AP connection and Data related packets')
    return parser.parse_args()
    # ref epilog, https://stackoverflow.com/a/50021771
    # ref nargs='*'', https://stackoverflow.com/a/4480202
    # ref no '--n' parameter, https://stackoverflow.com/a/21998252
    #
    # examples for reference
    # group.add_argument('--cache_core', action='store_true', default=None, help='Assume a "compiler.cache_core" value of true')
    # group.add_argument('--no_cache_core', dest='cache_core', action='store_false', help='Assume a "compiler.cache_core" value of false')
    # group.add_argument('--preferences_env', nargs='?', action='store', type=check_env, const="ARDUINO15_PREFERENCES_FILE", help=argparse.SUPPRESS)


def processFilter(filter_str, filter_good, filter_all, filter_session):
    """
    These values are based on "./esp32s3/include/esp_wifi/include/esp_wifi_types.h"
    At this writing, ESP32, ESP32-S2, ESP32-S2, and ESP32-C3 have identical "esp_wifi_types.h" files.
    """
    # The SDK uses a value of 0xFFFFFFFF for WIFI_PROMIS_FILTER_MASK_ALL. We borrow some unused bit possitions for some custom options
    # And, replace k_filter_all with k_filter_mask_all later.
    k_filter_all            = (0xFF80007F)  # Mask of know filter bits used by SDK, needs to be verified with each new SDK update
    k_filter_mask_all       = (0xFFFFFFFF)  # WIFI_PROMIS_FILTER_MASK_ALL,           filter/keep all packets
    k_filter_mgmt           = (1<<0)        # WIFI_PROMIS_FILTER_MASK_MGMT,          packets w/type WIFI_PKT_MGMT
    k_filter_ctrl           = (1<<1)        # WIFI_PROMIS_FILTER_MASK_CTRL,          packets w/type WIFI_PKT_CTRL
    k_filter_data           = (1<<2)        # WIFI_PROMIS_FILTER_MASK_DATA,          packets w/type WIFI_PKT_DATA
    k_filter_misc           = (1<<3)        # WIFI_PROMIS_FILTER_MASK_MISC,          packets w/type WIFI_PKT_MISC
    k_filter_data_mpdu      = (1<<4)        # WIFI_PROMIS_FILTER_MASK_DATA_MPDU,     MPDU a kind of WIFI_PKT_DATA
    k_filter_data_ampdu     = (1<<5)        # WIFI_PROMIS_FILTER_MASK_DATA_AMPDU,    AMPDU a kind of WIFI_PKT_DATA
    k_filter_fcsfail        = (1<<6)        # WIFI_PROMIS_FILTER_MASK_FCSFAIL,       FCS failed packets
    k_filter_ctrl_mask_all  = (0xFF800000)  # WIFI_PROMIS_CTRL_FILTER_MASK_ALL,      filter/keep all control packets
    k_filter_ctrl_wrapper   = (1<<23)       # WIFI_PROMIS_CTRL_FILTER_MASK_WRAPPER,  WIFI_PKT_CTRL w/subtype Control Wrapper
    k_filter_ctrl_bar       = (1<<24)       # WIFI_PROMIS_CTRL_FILTER_MASK_BAR,      WIFI_PKT_CTRL w/subtype Block Ack Request
    k_filter_ctrl_ba        = (1<<25)       # WIFI_PROMIS_CTRL_FILTER_MASK_BA,       WIFI_PKT_CTRL w/subtype Block Ack
    k_filter_ctrl_pspoll    = (1<<26)       # WIFI_PROMIS_CTRL_FILTER_MASK_PSPOLL,   WIFI_PKT_CTRL w/subtype PS-Poll
    k_filter_ctrl_rts       = (1<<27)       # WIFI_PROMIS_CTRL_FILTER_MASK_RTS,      WIFI_PKT_CTRL w/subtype RTS
    k_filter_ctrl_cts       = (1<<28)       # WIFI_PROMIS_CTRL_FILTER_MASK_CTS,      WIFI_PKT_CTRL w/subtype CTS
    k_filter_ctrl_ack       = (1<<29)       # WIFI_PROMIS_CTRL_FILTER_MASK_ACK,      WIFI_PKT_CTRL w/subtype ACK
    k_filter_ctrl_cfend     = (1<<30)       # WIFI_PROMIS_CTRL_FILTER_MASK_CFEND,    WIFI_PKT_CTRL w/subtype CF-END
    k_filter_ctrl_cfendack  = (1<<31)       # WIFI_PROMIS_CTRL_FILTER_MASK_CFENDACK, WIFI_PKT_CTRL w/subtype CF-END+CF-ACK

    k_filter_custom_session = (1<<16)       # Internal to WiFiPcap, not an SDK value.
                                            # Capture packets related to an AP connection
                                            # Removes null subtypes and noisy beacons and probes

    k_filter_custom_fcslen  = (1<<17)       # Internal to WiFiPcap, not an SDK value.
                                            # Experimental length includes fcs

    k_filter_custom_badpkt  = (1<<18)       # keep bad packets

    k_filter_custom_mask    = (0x00070000)

    k_filter_table = {
        "all":       k_filter_all,              # filter/keep all packets
        "all_mask":  k_filter_all,              # filter/keep all packets
        "good":      (k_filter_all & ~k_filter_fcsfail),
        #                                         packets with type:
        "mgmt":      k_filter_mgmt,             #   WIFI_PKT_MGMT
        "ctrl":      k_filter_ctrl,             #   WIFI_PKT_CTRL
        "data":      k_filter_data,             #   WIFI_PKT_DATA
        "misc":      k_filter_misc,             #   WIFI_PKT_MISC
        "mpdu":      k_filter_data_mpdu,        # MPDU a kind of WIFI_PKT_DATA
        "ampdu":     k_filter_data_ampdu,       # AMPDU a kind of WIFI_PKT_DATA
        "fcsfail":   k_filter_fcsfail,          # FCS failed packets
        #
        "ctrl_mask": k_filter_ctrl_mask_all,    # All WIFI_PKT_CTRL subtypes
        #                                         WIFI_PKT_CTRL with subtypes:
        "wrapper":   k_filter_ctrl_wrapper,     #   Control Wrapper
        "bar":       k_filter_ctrl_bar,         #   Block Ack Request
        "ba":        k_filter_ctrl_ba,          #   Block Ack
        "pspoll":    k_filter_ctrl_pspoll,      #   PS-Poll
        "rts":       k_filter_ctrl_rts,         #   RTS
        "cts":       k_filter_ctrl_cts,         #   CTS
        "ack":       k_filter_ctrl_ack,         #   ACK
        "cfend":     k_filter_ctrl_cfend,       #   CF-END
        "cfendack":  k_filter_ctrl_cfendack,    #   CF-END+CF-ACK
        #
        "session":   (k_filter_custom_session | k_filter_mgmt | k_filter_data),   # Capture packets related to an AP connection
        "fcslen":    k_filter_custom_fcslen,    # Experimental - FCS length include in packet length
        "bad":       (k_filter_custom_badpkt | k_filter_fcsfail),    # Bad packets
        "custom_mask": k_filter_custom_mask }

    supported_mnemonics = "all|all_mask|good|mgmt|ctrl|data|misc|mpdu|ampdu|fcsfail|ctrl_mas|wrapper|bar|ba|pspoll|rts|cts|ack|cfend|cfendack|session|fcslen"

    use_filter = None
    use_custom_filter = None
    custom_filter = 0
    filter_mask = 0
    if filter_str:
        items = filter_str.split('|')
        for key in items:
            if key.startswith("0x"):
                filter_mask |= int(key, 0)
            else:
                try:
                    filter_mask |= k_filter_table[key]
                except:
                    print(f'[!] Unknown filter mnemonic: "{key}"')
                    print(f'[!] Supported mnemonics: "{supported_mnemonics}"')
                    raise Exception(f'Unknown filter mnemonic: "{key}"')

        if k_filter_ctrl_mask_all & filter_mask:
            filter_mask = k_filter_ctrl | filter_mask


    # compose required bits to support selection
    if filter_mask:
        use_custom_filter = (filter_mask & k_filter_custom_mask)
        use_filter = filter_mask & ~k_filter_custom_mask
    elif filter_good:
        use_filter = k_filter_mask_all & ~k_filter_fcsfail
    elif filter_all:
        use_filter = k_filter_mask_all
    elif filter_session:
        use_filter = k_filter_data | k_filter_mgmt
        use_custom_filter = k_filter_custom_session

    if use_filter and (use_filter & k_filter_all) == k_filter_all:
        # If all the known SDK bits are set then most likely this should be
        # all ones like the SDK value fro WIFI_PROMIS_FILTER_MASK_ALL.
        use_filter = k_filter_mask_all

    return [ use_filter, use_custom_filter ]


def pickPort():
    ports = serial.tools.list_ports.comports()
    sortedports = sorted(ports)
    portcount = 0
    for port, desc, hwid in sortedports:
        # print("{}: {} [{}]".format(port, desc, hwid))
        portcount += 1
        print("[+] {} - {} - {}".format(portcount, port, desc))

    maxport = portcount
    if portcount == 0:
        print("[+] No Serial ports found")
        return None
    elif portcount == 1:
        serialport = sortedports[0].device
    else:
        try:
            choice = 1;
            chose = input(f'[?] Select a serial port (default "{choice}"): ')
            if chose != "":
                choice = int(chose)
            if choice > portcount:
                print("\n[+] Not a valid selection")
                return None
            serialport = sortedports[choice-1].device
        except KeyboardInterrupt:
            return None

    print(f'[*] Using serial port "{serialport}"')
    return serialport


def connectESP32(port, channel, filter, unicast, multicast, time_sync):
    global bpsRate

    def serialLineText(line):
        """
        Serial diagnostics can contain arbitrary bytes before the PCAP stream
        starts; keep the handshake log printable without hiding bad bytes.
        """
        return line.rstrip(b'\r\n').decode(errors='backslashreplace')

    retry = 3
    canBreak = False
    while not canBreak:
        try:
            ser = serial.Serial(None, bpsRate)
            ser.port = port
            ser.dtr = ser.rts = True
            # ser.baudrate = bpsRate
            ser.open()

            # interrupt stream or wakeup esp32
            ser.write( b'\x04' )        # send ^D (EOT)
            ser.write( b'\x12' )        # send ^R (DC2 - ready)
            time.sleep(0.1)
            ser.reset_input_buffer()
            canBreak = True
        except KeyboardInterrupt:
            return None
        except:
            if retry > 0:
                retry -= 1
                time.sleep(0.3)
            else:
                print(f'[!] Serial port "{port}" open attempt failed!')
                return None

    print(f'[+] Connected to serial port: "{ser.name}"')

    while True:
        try:
            line = ser.readline()
        except KeyboardInterrupt:
            return None
        except:
            print("[!] Serial port connection closed/failed while reading port!")
            return None

        # Old decode() could fail on non-UTF-8 serial noise; serialLineText()
        # strips line endings and escapes undecodable bytes for safe logging.
        # print(f'[>] ESP32 -> "{line.decode()[:-1]}"')
        print(f'[>] ESP32 -> "{serialLineText(line)}"')
        if b"<<SerialPcap>>" in line:
            print("[+] Uploading options ...")
            break

    str = "P"
    if channel:
        str += f'C{channel}'

    if filter[0] != None:                   # SDK filter
        val = 0x0FFFF & (filter[0] >> 16)
        str += f'F{val}'
        val = 0x0FFFF & filter[0]
        str += f'f{val}'
    if filter[1] != None:                   # custome filter
        val = 0x0FFFF & (filter[1] >> 16)   #   only uses the upper 16 bits.
        str += f'S{val}'
    elif filter[0] != None:
        # Firmware preserves custom filter state unless an S command is sent.
        # Clear it when this run only requests SDK-level filtering.
        str += 'S0'

    if unicast:
        str += f'U{unicast[0]}u{unicast[1]}'
        if multicast:
            str += f'M{multicast[0]}m{multicast[1]}'
        else:
            str += f'M0m0'

    if time_sync:
        now = time.time_ns()    # returns time as an integer number of nanoseconds since the epoch
        microseconds = round(now / 1000)
        seconds = int(microseconds / 1000000)
        microseconds %= 1000000
        str += f'G{seconds}g{microseconds}X\n'
    else:
        str += f'X\n'

    cmd = str.encode()
    ser.write(cmd)
    ser.flush()
    print("[<] ESP32 <- {}".format(cmd))

    while True:
        try:
            line = ser.readline()
        except KeyboardInterrupt:
            return None
        except:
            print("[!] Serial port connection closed/failed while reading port!")
            return None

        # print(f'[>] ESP32 -> "{line.decode()[:-1]}"')
        print(f'[>] ESP32 -> "{serialLineText(line)}"')
        if b"<<PASSTHROUGH>>" in line:
            print("[+] Upload Complete ...")
            break

    print("[+] Stream started ...")
    # Use a short read timeout so the relay loop can notice Wireshark exit and
    # return to the cleanup path that sends EOT back to the ESP32.
    ser.timeout = 0.05
    return ser


def runWireshark(ser):
    """
        # Old path gave Wireshark the serial port directly, leaving Python mostly
        # waiting in communicate(). Keep Python in the relay loop so it can detect
        # Wireshark exit and send EOT to the ESP32 during cleanup.

        print("[+] Starting Wireshark ...")
        proc=subprocess.Popen([ wireshark_path, '-k', '-i', '-' ], stdin=ser)
        proc.communicate()
        # cmd='wireshark -k -i -'
        # proc=subprocess.Popen(shlex.split(cmd), stdin=ser, start_new_session=True)
        # proc=subprocess.Popen(shlex.split(cmd), stdin=ser)
    """
    print("[+] Starting Wireshark ...")
    # Keep Python in the middle instead of handing the serial object directly to
    # Wireshark, so this script can detect process exit and close the ESP32 side.
    proc=subprocess.Popen([ wireshark_path, '-k', '-i', '-' ], stdin=subprocess.PIPE)
    try:
        while ser.is_open and proc.poll() is None:
            data = ser.read(4096)
            if not data:
                continue
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except BrokenPipeError:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        proc.wait()


def runWiresharkWin32(ser):
    # Ref. https://wiki.wireshark.org/CaptureSetup/Pipes.md#way-3-python-on-windows
    # Ref. https://stackoverflow.com/a/13319731
    import win32pipe, win32file
    print("[!] Experimental, Starting Wireshark ...")

    # create the named pipe \\.\pipe\wireshark
    pipe = win32pipe.CreateNamedPipe(
        r'\\.\pipe\wireshark',
        win32pipe.PIPE_ACCESS_OUTBOUND,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536,
        300,
        None)

    proc=subprocess.Popen([ wireshark_path_win32, r'-k', r'-i', r'\\.\pipe\wireshark' ])

    # pass serial pcap data through pipe to Wireshark
    try:
        win32pipe.ConnectNamedPipe(pipe, None)  # Wait for connection to pipe
        print("[+] Pipe Connected")

        while ser.is_open:
            if 0 < ser.in_waiting:
                data = ser.read(ser.in_waiting)
                win32file.WriteFile(pipe, data)
            else:
                # Python processes typically use a single thread because of the GIL.
                # We are all that is running? Do any of these libraries have
                # background threads? Leave this sleep for now.
                time.sleep(0.01)
    except:
        pass
    finally:
        pass

    win32file.CloseHandle(pipe)
    return None


def processAddress(unicast, oui):
    # unicast parsing also works for multicast
    if unicast:
        addr = re.split(':|,|-|\.| ', unicast)
        if 6 != len(addr):
            print(f'[!] Bad formatting "{unicast}" should be 6 bytes long')
            raise Exception(f'Bad address formatting')
            return [0, 0]
        msb = int(addr[0], 16)*(256*256) + int(addr[1], 16)*256 + int(addr[2], 16)
        lsb = int(addr[3], 16)*(256*256) + int(addr[4], 16)*256 + int(addr[5], 16)
    elif oui:
        addr = re.split(':|,|-|\.| ', oui)
        if 3 != len(addr):
            print(f'[!] Bad formatting "{oui}" should be 3 bytes long')
            raise Exception(f'Bad address formatting')
            return [0, 0]
        msb = int(addr[0], 16)*(256*256) + int(addr[1], 16)*256 + int(addr[2], 16)
        lsb = 0
    else:
        return None

    return [ msb, lsb ]


def runTkinterGui(args):
    """
    Small desktop control surface for esp32shark.py.

    First pass intentionally launches this same script as a child process instead
    of duplicating the serial/Wireshark relay in Tkinter callbacks. That keeps
    the proven CLI path as the single source of truth while giving us a place to
    grow controls.

    Live channel/filter changes while Wireshark stays open will need firmware
    support for a sideband control command. The current serial protocol
    re-enters the PCAP handshake and sends a new PCAP file header, which should
    not be injected into one already-running Wireshark stdin stream.
    """
    try:
        import tkinter as tk
        from tkinter import ttk
        from tkinter import messagebox
    except Exception as ex:
        print(f"[!] Tkinter is not available: {ex}")
        return 1

    class Esp32SharkGui:
        def __init__(self, root):
            self.root = root
            self.proc = None
            self.reader_thread = None

            root.title(f"{esp32_name} coPilot")
            root.geometry("720x520")
            root.minsize(620, 460)

            self.port_var = tk.StringVar()
            self.channel_var = tk.IntVar(value=args.channel if args.channel else 6)
            self.filter_var = tk.StringVar(value="Session")
            self.time_sync_var = tk.BooleanVar(value=args.time_sync)
            self.status_var = tk.StringVar(value="Idle")

            self.build_widgets()
            self.refresh_ports()

        def build_widgets(self):
            outer = ttk.Frame(self.root, padding=14)
            outer.pack(fill=tk.BOTH, expand=True)

            title = ttk.Label(outer, text=f"{esp32_name} coPilot", font=("TkDefaultFont", 18, "bold"))
            title.pack(anchor=tk.W)

            subtitle = ttk.Label(
                outer,
                text="USB/Wireshark launcher with simple capture controls. Apply changes by restarting capture.",
                foreground="#666666")
            subtitle.pack(anchor=tk.W, pady=(2, 14))

            controls = ttk.LabelFrame(outer, text="Capture")
            controls.pack(fill=tk.X)

            ttk.Label(controls, text="Serial port").grid(row=0, column=0, sticky=tk.W, padx=8, pady=8)
            self.port_box = ttk.Combobox(controls, textvariable=self.port_var, state="readonly", width=34)
            self.port_box.grid(row=0, column=1, sticky=tk.EW, padx=8, pady=8)
            ttk.Button(controls, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, padx=8, pady=8)

            ttk.Label(controls, text="Channel").grid(row=1, column=0, sticky=tk.W, padx=8, pady=8)
            channel_spin = ttk.Spinbox(controls, from_=1, to=max_channel, textvariable=self.channel_var, width=8)
            channel_spin.grid(row=1, column=1, sticky=tk.W, padx=8, pady=8)

            ttk.Label(controls, text="Filter").grid(row=2, column=0, sticky=tk.W, padx=8, pady=8)
            self.filter_box = ttk.Combobox(
                controls,
                textvariable=self.filter_var,
                state="readonly",
                values=("Previous", "Session", "Good", "All", "Mgmt + Data", "Bad FCS"))
            self.filter_box.grid(row=2, column=1, sticky=tk.EW, padx=8, pady=8)

            ttk.Checkbutton(controls, text="Sync PCAP start time from this computer", variable=self.time_sync_var).grid(
                row=3, column=0, columnspan=3, sticky=tk.W, padx=8, pady=8)

            controls.columnconfigure(1, weight=1)

            actions = ttk.Frame(outer)
            actions.pack(fill=tk.X, pady=12)
            self.start_button = ttk.Button(actions, text="Start Wireshark", command=self.start_capture)
            self.start_button.pack(side=tk.LEFT)
            self.stop_button = ttk.Button(actions, text="Stop", command=self.stop_capture, state=tk.DISABLED)
            self.stop_button.pack(side=tk.LEFT, padx=(8, 0))
            ttk.Label(actions, textvariable=self.status_var).pack(side=tk.RIGHT)

            note = ttk.Label(
                outer,
                text="Changing controls during capture does not affect the running stream yet. Stop and Start to apply.",
                foreground="#884400")
            note.pack(anchor=tk.W, pady=(0, 8))

            log_frame = ttk.LabelFrame(outer, text="Log")
            log_frame.pack(fill=tk.BOTH, expand=True)
            self.log_text = tk.Text(log_frame, height=14, wrap=tk.WORD)
            self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            self.log_text.configure(yscrollcommand=scroll.set)

            self.root.protocol("WM_DELETE_WINDOW", self.close)

        def log(self, message):
            self.log_text.insert(tk.END, message.rstrip() + "\n")
            self.log_text.see(tk.END)

        def refresh_ports(self):
            ports = sorted(serial.tools.list_ports.comports())
            labels = [port.device for port in ports]
            self.port_box["values"] = labels

            if args.port and args.port in labels:
                self.port_var.set(args.port)
            elif labels and not self.port_var.get():
                self.port_var.set(labels[0])

            self.log("Ports: " + (", ".join(labels) if labels else "none found"))

        def filter_args(self):
            selected = self.filter_var.get()
            if selected == "Previous":
                return []
            if selected == "Session":
                return ["--filter_session"]
            if selected == "Good":
                return ["--filter_good"]
            if selected == "All":
                return ["--filter_all"]
            if selected == "Mgmt + Data":
                return ["--filter_mask", "mgmt|data"]
            if selected == "Bad FCS":
                return ["--filter_mask", "bad"]
            return []

        def build_command(self):
            port = self.port_var.get()
            if not port:
                messagebox.showwarning("No Port", "Select a serial port first.")
                return None

            command = [
                sys.executable,
                os.path.abspath(__file__),
                "--port", port,
                "--channel", str(self.channel_var.get())
            ]

            command.extend(self.filter_args())

            if not self.time_sync_var.get():
                command.append("--no_time_sync")

            return command

        def start_capture(self):
            if self.proc and self.proc.poll() is None:
                self.log("Capture is already running.")
                return

            command = self.build_command()
            if not command:
                return

            self.log("[GUI] Starting: " + " ".join(shlex.quote(part) for part in command))
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self.proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env)

            self.status_var.set("Running")
            self.start_button.configure(state=tk.DISABLED)
            self.stop_button.configure(state=tk.NORMAL)
            self.reader_thread = None

            # Tkinter widgets must only be updated on the GUI thread. The reader
            # thread hands each line back to root.after().
            import threading
            self.reader_thread = threading.Thread(target=self.read_child_output, daemon=True)
            self.reader_thread.start()

        def read_child_output(self):
            try:
                for line in self.proc.stdout:
                    self.root.after(0, self.log, line)
            except Exception as ex:
                self.root.after(0, self.log, f"[GUI] Reader stopped: {ex}")
            finally:
                self.root.after(0, self.child_finished)

        def child_finished(self):
            if self.proc and self.proc.poll() is None:
                return

            self.status_var.set("Idle")
            self.start_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)

        def stop_capture(self):
            if not self.proc or self.proc.poll() is not None:
                self.child_finished()
                return

            self.log("[GUI] Stopping capture ...")
            try:
                # SIGINT gives the child script a chance to send EOT to the ESP32
                # and close the serial port cleanly.
                self.proc.send_signal(signal.SIGINT)
                self.root.after(2500, self.force_stop_if_needed)
            except Exception as ex:
                self.log(f"[GUI] Stop failed: {ex}")

        def force_stop_if_needed(self):
            if self.proc and self.proc.poll() is None:
                self.log("[GUI] Capture did not stop cleanly; terminating child process.")
                self.proc.terminate()

        def close(self):
            self.stop_capture()
            self.root.after(300, self.root.destroy)

    root = tk.Tk()
    Esp32SharkGui(root)
    root.mainloop()
    return 0


def main():
    default_encoding = get_encoding()

    try:
        args = parseArgs()

        if args.gui:
            return runTkinterGui(args)

        if args.no_addr:
            unicast = [0, 0]
            multicast = None
        else:
            unicast = processAddress(args.unicast, args.oui)
            if args.broadcast:
                multicast = [ 0x0FFFFFF, 0x0FFFFFF ]
            else:
                multicast = processAddress(args.multicast, None)

        filter = processFilter(args.filter_mask, args.filter_good, args.filter_all, args.filter_session)
    except:
        print("[+] Exiting ...")
        return 1

    if args.port:
        port = args.port
    else:
        port = pickPort()
        if not port:
            print("[+] Exiting ...")
            return 1

    print(f'[+] port          ="{port}"')
    print(f'[+] channel       ="{args.channel}"')
    if filter[0]:
        print(f'[+] filter_mask   ="{filter[0]:#08x}"')
    else:
        print('[+] filter_mask   ="None"')

    if filter[1]:
        print(f'[+] custom_filter ="{filter[1]:#08x}"')
    else:
        print('[+] custom_filter ="None"')

    if unicast:
        print(f'[+] unicast       ="{unicast}"')
    # elif oui:
    #     print(f'[+] --oui="{oui}"')

    if multicast:
        print(f'[+] multicast     ="{multicast}"')

    print(f'[+] set time      ="{args.time_sync}"')
    # sys.stdout.flush()

    ser = connectESP32(port, args.channel, filter, unicast, multicast, args.time_sync)
    if None == ser:
        print("[+] Exiting ...")
        return 1

    if not args.testing:
        system = platform.system()
        if "Windows" == system:
            runWiresharkWin32(ser)
        else:
            runWireshark(ser)

    try:
        ser.write( b'\x04' )        # send ^D (EOT)
        ser.flush()
        ser.dtr = ser.rts = False
        ser.close()
    except:
        pass

    print("[+] Done.")
    return 0


if __name__ == '__main__':
    rc = 1
    try:
        rc = main()
    except:
        print(traceback.format_exc())
        print("[!] Oops!")
    sys.exit(rc)
