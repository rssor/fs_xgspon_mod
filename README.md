# FS.com XGS-ONU-25-20NI AT&T Modification Utility
This utility makes the necessary changes to the FS.com XGS-PON module to allow it to operate on AT&T's XGS-PON fiber offerings. It attempts to do so as safely as possible, reverting automatically to a stock state if it is ever power cycled twice in quick succession.

## Disclaimers
Bypass the provided BGW320 at your own risk -- no matter how you go about it it is detectable and AT&T will find you if they go looking. This modification makes the minimum set of changes that I believe are necessary to get online but is intentionally trivially detectable. My rationale for this is that if anybody goes looking for these then chances are the devices are misbehaving and I'm not interested in making anybody's job harder than it needs to be.

Bypasses are detectable regardless of whether this device is used or any other (e.g. Azores D20 or WAS-110) -- the BGW320 hosts a variety of management services that won't be accessible from any customer bypassing provided equipment.

This particular FS.com device is actually a CIG XG-99S which is available under a variety of different brands. There is an entire family of devices running very similar firmwares that can likely also be modified in roughly the same way, though modifications to this utility would be required to support them. Of particular interest are the CIG XG-99M devices (best known as the FOX-222) which can be found for $30-$50 online as of writing and which I plan to look at in the near future.

While this modification attempts to be as safe _as possible_ it's much less safe than running an unmodified device. Although the device has two firmware slots they share the userdata partition that gets mounted to `/mnt/rwdir/`. During boot all CIG firmwares check for `/mnt/rwdir/setup.sh` and run it if it exists. This is done before the PON stack starts, so if anything goes wrong *it will never come online* and you will need UART access and micro-soldering skills to recover the device. For this reason, the modification disarms itself as the first action it takes during every boot -- that is the _only_ safety mechanism available.

## Requirements
- Python 3.6+
- The `install` command requires layer 2 adjacency to the stick (e.g. NO ROUTERS between you and the device, you have an address in `192.168.100.0/24`)
- The `GPONxxxxxxxx` serial of the stick (you generally need to ask your FS.com rep for this, it's not included with the device as of August 2023)
- Stick running firmware `R4.4.20.018` or `R4.4.20.022` (other versions _may_ be safe)

This utility has been tested on:
- openSUSE Leap 15.4
- Windows 11
- macOS 13.5

This utility is built on:
- Ubuntu 22.04.2 LTS

## Features
- Ethernet UNI moved from slot 10 to slot 1 in MIB entities, thus becoming compatible with AT&T bridge pack configurations
- Disables traffic filtering when the Dot1X Port Extension Package (ME 290) is configured to filter all traffic
- Uses serial provided to mod instead of the serial in EEPROM to allow the device to revert cleanly if the fail-safe triggers
- Sets appropriate equipment id for NOKA/HUMA BGW320 devices depending on the provided serial
- Starts `dropbear` 2 minutes or so after device boot for more convenient administration (no idle timeout)

## Usage

By convention the documentation below uses `GPON227000fe` to refer to the serial of the FS.com device and `HUMA12ab34cd` to refer to the ONT ID of your AT&T BGW320 device found on the bottom label.

Skip to [Installation](#installation) and [Enabling Persistence](#enabling-persistence) if you just want to get online.

### Password Generation

Helper command to generate both sets of credentials from a provided serial. This is helpful if FS.com assigned you a sales rep that doesn't know how to get users online with these sticks and you're forced to brute force your stick credentials. By default only the telnet credentials are usable as nothing starts `dropbear` on stock firmwares.

```
./fs_xgspon_mod.py genpw GPON227000fe
Creds for FS.com XGS-PON stick with serial GPON227000fe:
  Telnet: GPON227000fe / mbdu7pVX
     SSH:      ONTUSER / vjyKsHYsU2Aym5Nn
```

The HMAC key used to derive passwords appears to be different between the various OEM customers, so I don't think this works for anything except the FS.com sticks.

I suspect the serials take the form `GPONyymsssss` where `yy` is year, `m` is month, and `sssss` is number within run, but `yym` could be just batch numbers. Production runs seem to be very small so brute force won't take much time if you can guess roughly when your stick was manufactured. I have yet to see any serial with `sssss` greater than `000fe`.

### Telnet

Helper command so that you only need to remember the serial. Drops you immediately to an enabled `#ONT>` prompt.

```
./fs_xgspon_mod.py telnet GPON227000fe
enable
#ONT>
```

Automatically connects to the device, runs the `enable` command, and drops you do the ONT command prompt directly. If you want access to a shell, run `/s/s`. Ctrl-c to exit.

### Installation

Ensure that you're sitting adjacent to the stick on the network and that you have an address in the `192.168.100.0/24` subnet. The stick is at `192.168.100.1`. Ensure that your machine is configured to allow conncections on port `8172`. Activating the mod for a single boot only requires one command:

```
./fs_xgspon_mod.py install GPON227000fe HUMA12ab34cd
```

If installation fails chances are the stick isn't able to connect back to the machine you're running the utility from. It runs an HTTP server on port `8172` for the duration of installation that the stick needs to be able to connect to. I recommend punching a hole for all connections from `192.168.100.1` to port `8172`, at least when you need to run the installation command.

This will install everything necessary into `/mnt/rwdir/` on the device and set it up so that the next boot will take place with the mod active. By default every boot will delete the file necessary to support persistence so you'll need to run this command again if there's more than one power cycle.

After reboot the device will come up with the serial you provided as the second argument, and therefore you would use that new serial to connect via telnet. This also provides a quick way to determine what state your stick is in: see which serial needs to be passed to get dropped to a prompt, then you know if the mod is active or not.

After the stick has rebooted and you've confirmed that you can get online you may then want to move on to [enabling persistence](#enabling-persistence).

### Enabling Persistence

Persistence allows the modification to automatically re-arm itself for the next boot after a ~100 second timer expires.

```
./fs_xgspon_mod.py persist HUMA12ab34cd
```

Several minutes after the device has been booted with the mod active it becomes possible to enable persistent mode. The wait is implemented in order to attempt to make it impossible to enable persistence without proving the device can come online _enough_ to be recoverable. While this is implemented as a 100 second wait in the `libvos` shim, realistically it winds up being a bit over 2 minutes.

This will fail if the device wasn't booted with the mod active or if you haven't waited long enough since it booted with the mod active.

If you are able to connect to the device via SSH then this command should be functional. The shim starts dropbear at the same time as persistence becomes allowed.

### Fail-safe Recovery

In the event the failsafe triggers due to poorly timed power outages recovery is possible with only a few commands. Remember to use the serial in the device's EEPROM, either the one provided by FS.com reps if you didn't change it, or whatever you changed it to if you used the built-in commands to do so. Simply remove `/mnt/rwdir/disarmed` and reboot and the modification should be active again.

```
./fs_xgspon_mod.py telnet GPON227000fe
enable
#ONT> /s/s
/s/s
#ONT/system/shell>rm /mnt/rwdir/disarmed
rm /mnt/rwdir/disarmed
#ONT/system/shell>reboot
reboot
```

Wait a few minutes and it should come back online, responding to your AT&T NOKA/HUMA serial and getting you back online.

## Thanks To
- [miguemely](https://github.com/miguemely) - Initial testing, firmware dumps
- [YuukiJapanTech](https://github.com/YuukiJapanTech) - Assembling the spectacular resources at https://github.com/YuukiJapanTech/CA8271x/
- SipWannabe - Testing

## References
- https://github.com/YuukiJapanTech/CA8271x
- https://hack-gpon.org/xgs/ont-nokia-xs-010x-q/
