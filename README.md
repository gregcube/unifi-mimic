unifi-mimic
===========

Connect directly to UNVR with UniFi Protect mobile app when on
different layer 3 network.

Requirements
------------
* libnet-1.1.x or later (https://github.com/libnet/libnet)

``` console
sudo apt install libnet1-dev
```

Compile
-------
``` console
gcc unifi-mimic.c -lnet -o unifi-mimic
```

Usage
-----
**Step 1**: Run unifi-mimic on the same L3 network as your UNVR.

``` console
./unifi-mimic -D -i <interface>
```

This will send a UDP discovery packet on port 10001.  A file will be created
for each UniFi device that responds.  The file(s) will be named by IP address
of the discovered device and will contain UDP payload data.

**Step 2**: Run unifi-mimic on the same L3 network as the device that runs the
UniFi Protect mobile app.  Copy the file from Step 1 and specify it as
a command line argument.

``` console
./unifi-mimic -L -p <file> -i <interface>
```

For example, if your UNVR has IP address 192.168.1.10, copy the file
named "192.168.1.10" to the same directory as unifi-mimic and run:

``` console
./unifi-mimic -L -p 192.168.1.10 -i eth0
```

Now whenever UniFi Protect looks for your UNVR, unifi-mimic will respond with
the proper payload and you'll be directly connected.  You may need to close
and re-open the UniFi Protect app.  Also ensure both networks are able
to talk to each other, i.e. no firewall is blocking communication.

You can also fork unifi-mimic to run as a background process with the -f flag.

``` console
./unifi-mimic -L -p 192.168.1.10 -i eth0 -f
```

Notes
-----
This has only been tested on a Raspberry Pi 4 with a UNVR and the
UniFi Protect mobile app on Android.

Inspired by https://github.com/bahamas10/unifi-proxy
