#! /usr/bin/python3
##
##
#
#
#
############################################
############################################
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of various ways to display a packet in scapy.
"""
from __future__ import print_function

import argparse
import os
import subprocess
from sys import platform, stderr
import tempfile

# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy

try:
    input = raw_input
except NameError:
    pass


def make_packet():
    """
        Make a ping packet for example purposes.
    """
    ether = scapy.Ether(
        src='fe:ed:ad:ea:dc:0d',
        dst='d0:cd:ae:da:de:ef',
        type=2048,
    )

    ip = scapy.IP(  # pylint: disable=invalid-name
        frag=0,
        src='192.0.2.201',
        proto=1,
        tos=0,
        dst='203.0.113.102',
        chksum=22360,
        len=84,
        options=[],
        version=4,
        flags=2,
        ihl=5,
        ttl=64,
        id=4492,
    )

    icmp = scapy.ICMP(
        gw=None,
        code=0,
        ts_ori=None,
        addr_mask=None,
        seq=101,
        ptr=None,
        unused=None,
        ts_rx=None,
        chksum=49274,
        reserved=None,
        ts_tx=None,
        type=8,
        id=3408,
    )

    data = scapy.Raw(
        load='some-data',
    )

    packet = ether/ip/icmp/data

    return packet


def display(packet, filters=None, layer=None):
    """
        Display a packet in various ways.
    """
    if filters is None:
        filters = DISPLAYS.keys()

    if layer:
        # Get just this layer otherwise the layer and all contained
        # layers will be displayed
        displayed = packet.getlayer(layer).copy()
        displayed.remove_payload()
        message = 'Layer {layer} {selection}:'
    else:
        displayed = packet
        message = 'Packet {selection}:'

    for selected in filters:
        if selected in DISPLAYS:
            print(message.format(
                selection=selected.replace('_', ' '),
                layer=layer,
            ))
            DISPLAYS[selected](displayed)
            print('')
        else:
            invalid(selected)


def invalid(selected):
    print('Could not find layer {sel}'.format(
        sel=selected,
    ))
    print('')


def show_details(packet):
    packet.show()


def show_fields(packet):
    print(packet.fields)


def show_summary(packet):
    print(packet.summary())


def show_command(packet):
    print(packet.command())


def show_pdf(packet):
    print('Creating and displaying PDF dissection of packet...')
    generated = False
    try:
        tempdir = tempfile.mkdtemp()
        dumpfile = os.path.join(tempdir, 'pingpacket')
        packet.psdump(dumpfile)
        generated = True
        # This actually dumps with an eps extension
        dumpfile = dumpfile + '.eps'

        if 'linux' in platform:
            subprocess.check_call(['xdg-open', dumpfile])
        elif platform == 'darwin':
            subprocess.check_call(['open', dumpfile])
        elif platform == 'win32':
            subprocess.check_call(
                'start {dumpfile}'.format(dumpfile=dumpfile),
                shell=True,
            )
    except Exception:
        # PDF generation and reading is somewhat flaky. Cope.
        stderr.write('PDF generation/reading problem. Sorry.\n')
    finally:
        if generated:
            input('Press enter when you have finished viewing the PDF...')
            os.unlink(dumpfile)
        os.rmdir(tempdir)


def get_packet_layer_names(packet):
    layer_names = []
    depth = 0
    while True:
        try:
            layer_names.append(packet[depth].name)
            depth += 1
        except IndexError:
            return layer_names


DISPLAYS = {
    'details': show_details,
    'summary': show_summary,
    'creation_code': show_command,
    'pdf': show_pdf,
    'fields': show_fields,
}


if __name__ == '__main__':
    packet = make_packet()

    parser = argparse.ArgumentParser(
        description='Display packets in... ways.',
    )

    parser.add_argument(
        '-f', '--filters',
        help='Packet displays to show.',
        nargs='+',
        choices=DISPLAYS.keys(),
    )

    parser.add_argument(
        '-l', '--layers',
        help="Get only specified layers.",
        nargs='+',
        choices=get_packet_layer_names(packet),
    )

    args = parser.parse_args()

    filters = args.filters
    layers = args.layers

    if layers:
        for layer in layers:
            display(packet, filters=filters, layer=layer)
    else:
        display(packet, filters=filters)


########################
###############################################
##
##
