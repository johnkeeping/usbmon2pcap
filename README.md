usbmon2pcap - convert usbmon text traces to pcap
================================================

This small utility does exactly what it says: converts a text usbmon
capture (in either the 't' or 'u' format) to a pcap file which can then
be analysed in Wireshark.

Example:

    # cat /sys/kernel/debug/usbmon/1u >1u.log
    ^C
    $ usbmon2pcap -o 1u.pcap 1u.log

Note that usbmon's text output is limited to 32 bytes of data in any
packet, so you are likely to see "packet size limited during capture" in
Wireshark.
