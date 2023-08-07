#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
from itertools import islice, chain
from threading import Thread
from telnetlib import Telnet
from pathlib import Path
import hmac

# if you add any new fields that need to be customed, you will
# also need to adjust PayloadHandler.do_GET()
CONFIG_TEMPLATE="""ETH10GESLOT=1
EepEqVendorID=GPON
EepEqSerialNumber=GPON12345678
EepVDSL2SerialNumber=        VDSLSerialNumberGPON12345678
EepEqVersionID=GPON
EepEqID=XG-99S
"""

VENDOR_SPECIFIC = {
    "HUMA": "iONT320500G",
    "NOKA": "iONT320505G",
}

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

class CigTelnet(Telnet):
    def __init__(self, serial):
        serial = serial[:4].upper() + serial[4:].lower()

        super().__init__("192.168.100.1", 23)
        self._in_shell = False

        self.read_until(b"Login as:")
        self.write(f"{serial}\n".encode("utf-8"))
        self.read_until(b":")
        self.write(f"{VOS_HmacMD5(serial.upper(), 8)}\n".encode("utf-8"))
        self.read_until(b"ONT>")
        self.write(b"enable\n")

    def sh_cmd(self, cmd, timeout=2):
        if not self._in_shell:
            self._in_shell = True
            self.write(b"/s/s\n")
            self.read_until(b"shell>", timeout)

        if not cmd.endswith("\n"):
            cmd += "\n"

        self.write(cmd.encode("utf-8"))
        res = self.read_until(b"shell>", timeout)
        if b"shell>" not in res:
            raise CigTimeout("CigTelnet command timed out")
        return res.decode("utf-8")

class PayloadHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, serial=None, **kwargs):
        self.vendor = serial[:4]
        self.serial = serial[4:].lower()
        self.eqid = VENDOR_SPECIFIC[self.vendor]
        super().__init__(*args, directory=Path(__file__).parent / "payload", **kwargs)

    def do_GET(self):
        if self.path=="/config":
            self.send_response(200)
            self.send_header("Content-type", "html")
            self.end_headers()
            self.wfile.write(CONFIG_TEMPLATE \
                             .replace("GPON", self.vendor) \
                             .replace("12345678", self.serial) \
                             .replace("XG-99S", self.eqid) \
                             .encode("utf-8"))
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

def telnet(args):
    with CigTelnet(args.serial) as tn:
        tn.interact()

def install(args):
    assert args.att_serial[:4] in VENDOR_SPECIFIC

    class PayloadServer(HTTPServer):
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address, self, serial=args.att_serial)

    print("Connecting via telnet...")
    with CigTelnet(args.gpon_serial) as tn:
        (addr, _) = tn.get_socket().getsockname()

        with PayloadServer(("", 8172), PayloadHandler) as ps:
            (_, port) = ps.socket.getsockname()
            Thread(target=ps.serve_forever, daemon=True).start()
            print(f"Webserver listening on {addr}:{port}")
            print("If this doesn't complete almost immediately, ensure there is no router between you and the device!")

            # ensure that if this goes Poorly we can power cycle our way out of it
            tn.sh_cmd("touch /mnt/rwdir/disarmed")
            tn.sh_cmd("[ -f /mnt/rwdir/setup.sh ] && rm /mnt/rwdir/setup.sh")

            # prevent a bad update from incorrectly persisting based on a safe prior version that
            # was persisting successfully by forcing people to re-enable it the long way
            tn.sh_cmd("[ -f /mnt/rwdir/payload_auto_rearm ] && rm /mnt/rwdir/payload_auto_rearm")

            try:
                assert "100%" in tn.sh_cmd(f"wget -O - {addr}:{port}/config > /mnt/rwdir/payload.cfg", 10)
                print("Payload configuration sent")

                assert "100%" in tn.sh_cmd(f"wget -O - {addr}:{port}/payload.tgz | tar xvzf - -C /mnt/rwdir/", 10)
            except (CigTimeout, AssertionError):
                print(f"Error: Stick was not able to connect back and download payload! Check firewall!")
                return

            assert "stage0.sh" in tn.sh_cmd("ls /mnt/rwdir/")

            tn.sh_cmd("ln -sf /mnt/rwdir/stage0.sh /mnt/rwdir/setup.sh")
            tn.sh_cmd("[ -f /mnt/rwdir/disarmed ] && rm /mnt/rwdir/disarmed")
            tn.sh_cmd("sync")

            print("Payload extracted -- press enter to reboot!")

            tn.write(b"reboot") # missing newline on purpose
            tn.interact()

def persist(args):
    print("Connecting via telnet...")
    with CigTelnet(args.att_serial) as tn:
        if "payload_postboot_dropbear" not in tn.sh_cmd("ls -l /tmp/"):
            print("Persistence not allowed yet -- has it been 3+ minutes since boot?")
            print("If it's been more than 3 minutes and the device is not listening for SSH connections, the mod is not active!")
            return

        tn.sh_cmd("[ -f /tmp/payload_postboot_dropbear ] && touch /mnt/rwdir/payload_auto_rearm")
        tn.sh_cmd("[ -f /mnt/rwdir/disarmed ] && rm /mnt/rwdir/disarmed")
        tn.sh_cmd("[ ! -f /mnt/rwdir/setup.sh ] && ln -s /mnt/rwdir/stage0.sh /mnt/rwdir/setup.sh")
        tn.sh_cmd("sync")

        print("Persistence now enabled -- as a fail safe, a power cycle between ~30 seconds and ~120 seconds after boot should restore to stock")

if __name__=="__main__":
    import argparse

    def parse_serial(serial):
        serial = serial.upper()

        if len(serial) != 12:
            raise argparse.ArgumentError("serial must be 12 characters")

        if serial[:4] not in ("GPON", "NOKA", "HUMA"):
            raise argparse.ArgumentError("vendor must be one of GPON, NOKA, HUMA")

        try:
            numeric = serial[4:].strip()
            assert len(numeric) == 8
            int(numeric, 16)
        except (ValueError, AssertionError):
            raise argparse.ArgumentError("numeric portion of serial must be valid hexadecimal")

        return serial

    p = argparse.ArgumentParser()
    s = p.add_subparsers()

    parse_genpw = s.add_parser("genpw")
    parse_genpw.add_argument("serial", type=parse_serial)
    parse_genpw.set_defaults(func=genpw)

    parse_telnet = s.add_parser("telnet")
    parse_telnet.add_argument("serial", type=parse_serial)
    parse_telnet.set_defaults(func=telnet)

    parse_install = s.add_parser("install")
    parse_install.add_argument("gpon_serial", type=parse_serial)
    parse_install.add_argument("att_serial", type=parse_serial)
    parse_install.set_defaults(func=install)

    parse_persist = s.add_parser("persist")
    parse_persist.add_argument("att_serial", type=parse_serial)
    parse_persist.set_defaults(func=persist)

    args = p.parse_args()
    args.func(args)

