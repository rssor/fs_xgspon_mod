# FS.com XGS-ONU-25-20NI AT&T Modification Utility
This utility makes the necessary changes to the FS.com XGS-PON ONU to allow it to operate on AT&T (USA), Orange (FR), and other XGS-PON fiber offerings. It attempts to do so as safely as possible, reverting automatically to a stock state if it is ever power cycled twice in quick succession.

This particular FS.com device is actually a CIG XG-99S which is available under a variety of different brands. There is an entire family of devices running very similar firmwares that can likely also be modified in roughly the same way, though modifications to this utility would be required to support them. Of particular interest are the CIG XG-99M devices (best known as the FOX-222) which can be found for $30-$50 online as of writing and which I plan to look at in the near future.

While this modification attempts to be as safe _as possible_ it's much less safe than running an unmodified device. Although the device has two firmware slots they share the userdata partition that gets mounted to `/mnt/rwdir/`. During boot all CIG firmwares check for `/mnt/rwdir/setup.sh` and run it if it exists. This is done before the PON stack starts, so if anything goes wrong *it will never come online* and you will need UART access and micro-soldering skills to recover the device. For this reason, the modification disarms itself as the first action it takes during every boot -- that is the _only_ safety mechanism available.

Bypassing an ISP's ONT with your own is relatively trivial to detect if they care to look. If this concerns you, don't do it.

## Requirements
- Python 3.6+
- The `install` command requires layer 2 adjacency to the stick (e.g. NO ROUTERS between you and the device, you must have an address in `192.168.100.0/24`, port `8172` must be opened)
- The `GPONxxxxxxxx` serial of the stick (you generally need to ask your FS.com rep for this, it's not included with the device, or use the included brute force tools)
- Stick running firmware `R4.4.20.018` or `R4.4.20.022` (other versions _may_ be safe)
- If using the backdoor brute force feature (Linux only), the `pyroute2` pip package must be installed

This utility has been tested on:
- openSUSE Leap 15.4
- Windows 11
- macOS 13.5

This utility is built on:
- Ubuntu 22.04.2 LTS

## Features
- Ethernet UNI can be moved from slot 10 to slot 1 in MIB entities, thus becoming compatible with AT&T and Orange services
- Disables traffic filtering when the Dot1X Port Extension Package (ME 290) is configured to filter all traffic
- Uses serial provided to mod instead of the serial in EEPROM to allow the device to revert cleanly to stock config if the fail-safe triggers
- Sets appropriate equipment ID/hwver/swver automatically if it can be determined from the ISP/serial combo provided as arguments
- Starts `dropbear` sshd 2 minutes or so after device boot for more convenient administration (no idle timeout)
- Limited ability to modify/suppress Received Frame VLAN Tagging Operations Table rules found in Extended VLAN Tagging Operation Configuration Data (ME 171) (needed for Orange support)

## Usage

1. Download the mod from [the Releases page](https://github.com/rssor/fs_xgspon_mod/releases) and extract it on a device with L2 connectivity to the module
2. Obtain the serial for the FS.com ONU, either by emailing your FS.com rep, or using the [serial brute forcing](#serial-brute-forcing) functionality of this tool.
3. Run the [install](#installation) command with the information required by your ISP (at minimum serial, possibly also hwver, swver, and equipment ID)
4. Wait several minutes for device to reboot, ensure you have internet connectivity
5. Run the [persist](#enabling-persistence) command
6. (Optional) Add a cron job on your gateway/router (NOT THIS DEVICE) to run the [rearm](#rearm) command regularly to recover from the failsafe condition if it triggers due to poorly timed power interruptions

By convention the documentation below uses `GPON227000fe` to refer to the serial of the FS.com device and `HUMA12ab34cd` to refer to the serial of your ISP's ONT.

### Installation

Ensure that you're sitting adjacent to the stick on the network and that you have an address in the `192.168.100.0/24` subnet. The stick is at `192.168.100.1`. Ensure that your machine is configured to accept conncections on port `8172` (you may need to add a firewall allow rule for this!). Activating the mod for a single boot only requires one command:

```
# ATT
./fs_xgspon_mod.py install GPON227000fe att HUMA12ab34cd

# Frontier, with an assigned FRX523
./fs_xgspon_mod.py install GPON227000fe frontier FTRO12ab34cd --eqvid FRX523

# Any arbitrary ISP as long as you know the equipment id/hwver/swver and necessary ethernet uni slot
./fs_xgspon_mod.py install GPON227000fe manual ALCL12ab34cd --hwver SOMETHING --swver ELSE --eqvid EQUIPMENT --eth_slot 10

# Orange, with full example output
./fs_xgspon_mod.py install GPON227000fe orange SMBSXXXXXXXX
[+] Generated payload configuration:
      ETH10GESLOT=1
      EepEqVendorID=SMBS
      EepEqSerialNumber=SMBSXXXXXXXX
      EepVDSL2SerialNumber=        VDSLSerialNumberSMBSXXXXXXXX
      EepEqVersionID=SMBSXLB7400
      VLAN_MOD_RULES=838,2,8,8 838,-1,-2,0 840,5,-1,-1 840,0,8,8 840,-1,-2,0 851,5,-1,-1 851,6,-1,-1 851,0,8,8 851,-1,-2,0
[+] Telnet connection established, login successful
[+] Webserver listening on 192.168.100.10:8172

[!] If this doesn't complete almost immediately, ensure there is no router between you and the device!
[!] The stick MUST be able to connect back to this machine to retrieve the payload!
[!] Also double check that there are no firewall rules blocking traffic to port 8172.

[+] Disarmed any potential existing install
[+] Disabled auto-rearming if it was previously enabled
192.168.100.1 - - [05/Jan/2024 22:19:06] "GET /config HTTP/1.1" 200 -
[+] Stick retrieved payload configuration
192.168.100.1 - - [05/Jan/2024 22:19:06] "GET /payload.tgz HTTP/1.1" 200 -
[+] Stick retrieved and extracted payload
[+] Payload extracted -- press enter to reboot the ONU!
reboot

#ONT/system/shell>*** Connection closed by remote host ***
```

If installation fails chances are the stick isn't able to connect back to the machine you're running the utility from. It runs an HTTP server on port `8172` for the duration of installation that the stick needs to be able to connect to. I recommend punching a hole for all connections from `192.168.100.1` to port `8172`, at least when you need to run the installation command.

This will install everything necessary into `/mnt/rwdir/` on the device and set it up so that the next boot will take place with the mod active. It installs in a non-persistent mode, requiring use of the [rearm][#rearm] command after every boot or the use of the [persist](#enabling-persistence) command.

### Enabling Persistence

Persistence allows the modification to automatically re-arm itself approximately 100 seconds after PON stack initialization. It can only be turned on while the mod is active and the device has been powered on for several minutes in order to prove that the configuration results in a reachable device.

```
# remember to use the serial of your ISP's ONT, not the one the FS stick came with!
./fs_xgspon_mod.py persist HUMA12ab34cd
[+] Telnet connection established, login successful
[+] Persistence enabled
[+] As a fail safe, power cycling shortly after initial boot (~30-120 seconds) will deactivate persistence until rearmed
```

### Rearm

Rearm is used to either re-enable persistence after the fail-safe triggers, or to enable the mod for the next boot if it's in non-persistent mode. If it detects that the failsafe had been triggered it will automatically reboot.

Recommended use is to set this up on an hourly or similar cron job on your gateway (using the original serial as an argument!) so that if the failsafe triggers it will be automatically re-enabled.

```
# remember to use the original serial
./fs_xgspon_mod.py rearm GPON227000fe
[+] Telnet connection established, login successful
[+] Disarmed state cleared
[+] Detected that the failsafe triggered, rebooting device...
```

While the mod is active it will simply do nothing because the ISP serial is active, but if the mod ever inactivates it will be able to connect and thus re-enable persistence and reboot back into the mod.

### Serial Brute Forcing

FS.com doesn't distribute these with the serial you need to log in, requiring you to email your rep with the FS.com serial so they can look up the GPON serial for the stick. Fortunately, the serial number assignments are predictable and so there are two other options: brute forcing via telnet and brute forcing via a backdoor that CIG implements in a lot of their ONU offerings.

The serials take the form `GPONyymsssss` where `yy` is year (decimal, `23` for 2023), `m` is month (hex, `a` for October), and `sssss` is number within run. Production runs seem to be very small so brute force won't take much time if you can guess roughly when your stick was manufactured. I have yet to see any serial with `sssss` greater than `000fe`. These tools will try up through `00119` for each month.

#### CIG Backdoor Brute Force (Linux only!)

Brute forcing all possible serials should take around 20-30 seconds as of Jan 2024. It starts from the current month/year and works backwards, and assumes there were no units produced before Jan 2022.

```
# must be root (or have CAP_NET_RAW), raw sockets are needed to send frames with the CIG backdoor ethertype!
sudo ./fs_xgspon_mod.py discoverserial_cig
[+] Validated target reachable via telnet, check for ARP entries...
[+] Target reachable at MAC xxxxxxxxx from interface enp6s0 with MAC xxxxxxxxxx
[!] Beginning processing chunk of 1000 serials (next: GPON24100000)
[!] Beginning processing chunk of 1000 serials (next: GPON23b000e8)
...
[+] Telnet credentials: GPONXXXXXXXX / YYYYYYYY
```


#### Telnet Brute Force

This is able to test around one password every 3 seconds or so. Should be able to tell you your serial if you run it overnight. As of Jan 2024 it needs to test up to 7200 serials.

```
./fs_xgspon_mod.py discoverserial
[!] Attempting GPON24100000
...
[+] Telnet credentials: GPONXXXXXXXX / YYYYYYYY
```

### Telnet Wrapper

Helper command so that you only need to remember the serial. Drops you immediately to an enabled `#ONT>` prompt.

```
./fs_xgspon_mod.py telnet GPON227000fe
enable
#ONT>
```

Automatically connects to the device, runs the `enable` command, and drops you do the ONT command prompt directly. If you want access to a shell, run `/s/s`. Ctrl-c to exit.

### Telnet/SSH Password Generation

Helper command to generate both sets of credentials from a provided serial. This is helpful if FS.com assigned you a sales rep that doesn't know how to get users online with these sticks and you're forced to brute force your stick credentials. By default only the telnet credentials are usable as nothing starts `dropbear` on stock firmwares.

```
./fs_xgspon_mod.py genpw GPON227000fe
Creds for FS.com XGS-PON stick with serial GPON227000fe:
  Telnet: GPON227000fe / mbdu7pVX
     SSH:      ONTUSER / vjyKsHYsU2Aym5Nn
```

The HMAC key used to derive passwords appears to be different between the various OEM customers, so I don't think this works for anything except the FS.com sticks.


## Troubleshooting / Advanced

### Finding right ETH10GESLOT

If you appear to be in a real O5 state (VLAN rules populated by the OLT) but traffic isn't passing, check the bridgepack configuration to see how the OLT is configuring the bridge. If the wrong slot is in use, you'll see an error in the MEC log (`/system/log/show mec`) along the lines of the following:

```
      c161       31         mec_cc.c  515     4 -------->MEC update all connections [START]
      c166       31         mec_cc.c  965     4 update mp port
      c167       31         mec_cc.c 1249     4 Eth uni [0x0101] not found
      c167       31         mec_cc.c 1002     4 bridge port cfg data not complete [0x0101]
      c167       31        mec_cfg.c 1406     1 mec_CfgDscpChangedInRuntime[0]: this conneciton is not completed!
      c168       31         mec_cc.c  629     4 <--------MEC update all connections [END + 1]
```

This was taken from an unmodified stick (which defaults to using slot `10`, so the ETH UNI entity ID is `0x0a01`), but ATT was pushing a bridge config that would only work with an entity ID of `0x0101`. If you see an error like this, you'd need to add `--eth_slot 1` to your `install` command.

### VLAN_MOD_RULES

This device only supports up to 17 rules in the Received Frame VLAN Tagging Operation Table per UNI in ME 171. Some ISPs (namely Orange) require more than this number. This provides a facility through which rules can be effectively dropped before they are used during UNI configuration. Rules can be supplied using the `--vlan_rules` optional argument to the `install` command. Look at the rules in the Orange ISP implementation in the Python script for an explanation of how to craft them.

If you run `/s/m/show 506` from telnet and see 17 or fewer rules, you almost certainly don't need to use this functionality.

## Thanks To
- [miguemely](https://github.com/miguemely) - Initial testing, firmware dumps
- [YuukiJapanTech](https://github.com/YuukiJapanTech) - Assembling the spectacular resources at https://github.com/YuukiJapanTech/CA8271x/
- SipWannabe - Testing
- Mastah - Testing/Debugging Orange connectivity issues

## References
- https://github.com/YuukiJapanTech/CA8271x
- https://hack-gpon.org/xgs/ont-nokia-xs-010x-q/
