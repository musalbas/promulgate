import thread
import time
import netaddr
import socket

SUBTYPE_PROBE_REQUEST = 0b01000000
TYPE_MANAGEMENT       = 0b00000000

class Hoover:

    def __init__(self, interface):
        self._rawsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
            socket.htons(0x0003))
        self._rawsock.bind((interface, 0x0003))

        self._devices = {}

        thread.start_new(self._receiver, ())

    def _log_device(self, packetinfo):
        if packetinfo['source_mac'] not in self._devices:
            self._devices[packetinfo['source_mac']] = {'ssids': [],
                'org': packetinfo['source_org']}

        device = self._devices[packetinfo['source_mac']]

        device['last_seen'] = time.time()

        if packetinfo['ssid'] not in device['ssids']:
            device['ssids'].append(packetinfo['ssid'])

    def _read_probe_request_packet(self, rawpacket):
        if ord(rawpacket[26]) != SUBTYPE_PROBE_REQUEST | TYPE_MANAGEMENT:
            return False

        packetinfo = {}

        packetinfo['source_mac'] = rawpacket[36:42]

        source_org = netaddr.EUI(packetinfo['source_mac'].encode('hex'))
        try:
            source_org = source_org.oui.registration().org
            packetinfo['source_org'] = source_org
        except netaddr.core.NotRegisteredError:
            source_org = None

        packetinfo['ssid'] = rawpacket[52:52 + ord(rawpacket[51])]

        return packetinfo

    def _receiver(self):
        while True:
            rawpacket = self._rawsock.recvfrom(2048)
            packetinfo = self._read_probe_request_packet(rawpacket[0])

            if not packetinfo:
                continue

            self._log_device(packetinfo)

            print packetinfo
