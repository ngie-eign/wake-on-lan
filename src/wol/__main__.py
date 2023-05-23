#!/usr/bin/env python3
"""WakeOnLan script.

Based on example code which can be found on this Wikipedia page:
https://en.wikipedia.org/wiki/Wake-on-LAN#Creating_and_sending_the_magic_packet

Honor the license please by keeping the attribution; please also note any
restrictions contained in the license itself.

The "restricted" code is limited to ``send_magic_packet``. The rest I wrote from
scratch.

Example captured on date of original commit -- CCAS License at time of writing:
3.0 .

-Enji
"""

import argparse
import ipaddress
import logging
import re
import socket
import subprocess
import typing

import macaddress


Numeric = int | float

# This does not use ``echo`` like shown on wikipedia because it returns port 4 on
# OSX (4 -> legacy Apple echo service, per /etc/services).
DISCARD_PORT = socket.getservbyname("discard")


# Regular expressions for the Node container class.
ARP_MAC_IP_RE = re.compile(
    # e.g., `? (w.x.y.z) on ff:ff:ff:ff:ff:ff on int0 ...`
    r".+\((?P<ip_address>[\d+\.\d+\.\d+\.\d+]+)\) at "
    r"(?P<mac_address>[a-fA-F\d:]+) on .+"
)
NDP_MAC_IP_RE = re.compile(
    # e.g., `fe80::dead:beef%int0 ff:ff:ff:ff:ff:ff ...`
    r"(?P<ip_address>[a-fA-F\d:]+)%\S+\s+(?P<mac_address>[a-fA-F\d:]+)\s+.+"
)


class Node:
    """A simple container class for mac_address to ip_address mappings.

    The parameters in this class correspond with groups described in the above regular
    expressions.

    This class also handles some degree of data massaging/validation.
    """

    def __init__(self, mac_address: str, ip_address: str):
        self.mac_address: str = ":".join(
            "{:02x}".format(int(nibble, 16)) for nibble in mac_address.split(":")
        )
        self.ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address = (
            ipaddress.ip_address(ip_address)
        )


def send_magic_packet(mac_address: macaddress.MAC) -> None:
    """The logic that sends the actual magic packet.

    Arguments:
        mac_address: the MAC address to send the magic packet to.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    mac_address_str = str(mac_address).lower().replace("-", ":")
    logging.info("will send magic packet to: %s", mac_address_str)

    magic = b"\xff" * 6 + bytes(mac_address) * 16
    sock.sendto(
        magic,
        (
            "<broadcast>",
            DISCARD_PORT,
        ),
    )


def parse_ip_address_arg(values: str) -> str:
    """--ip-address argument parser/validator.

    This particular function takes a value, parses it for sanity, runs a command
    to map

    Arguments:
        value: an IPv4 or IPv6 address specified on the command line.

    Returns:
        A string representation of the MAC address.
    """
    ip_address = ipaddress.ip_address(values)
    if isinstance(ip_address, ipaddress.IPv4Address):
        command = ["arp", "-an"]
        pattern = ARP_MAC_IP_RE
    elif isinstance(ip_address, ipaddress.IPv6Address):
        command = ["ndp", "-an"]
        pattern = NDP_MAC_IP_RE
    else:
        raise AssertionError(f"Unhandled ipaddress type: {ip_address!r}")

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            check=True,
            encoding="utf-8",
            text=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as cpe:
        raise ValueError(f"Could not resolve MAC addresses via {command!r}") from cpe

    for line in proc.stdout.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        node = Node(**match.groupdict())
        if node.ip_address == ip_address:
            return node.mac_address

    raise ValueError(
        f"MAC address matching {values!r} not found in output from {command!r}; try "
        f"running arping or ndisc6, then rerun this script."
    )


def mac_address_to_bytes(mac_address: str) -> macaddress.MAC:
    """Return the bytes form of a given MAC address.

    Arguments:
        mac_address: a MAC address in str form.

    Raises:
        ValueError: value provided is not a valid MAC address.

    Returns:
        The MAC address in bytes representation.
    """
    return macaddress.parse(mac_address, macaddress.EUI48)


class IPAddressAction(argparse.Action):
    def __init__(
        self,
        option_strings: list[str],
        dest: str,
        *args,
        nargs: str | None = None,
        **kwargs,
    ):
        if nargs is not None:
            raise ValueError("nargs not supported.")
        super().__init__(option_strings, dest, *args, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values,
        option_string: str | None = None,
    ) -> None:
        typing.cast(str, values)
        mac_address = parse_ip_address_arg(values)
        setattr(namespace, self.dest, mac_address_to_bytes(mac_address))


def parse_target_from_args(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser()
    target_parser = parser.add_mutually_exclusive_group(required=True)
    target_parser.add_argument("--ip-address", action=IPAddressAction, dest="target")
    target_parser.add_argument(
        "--mac-address", dest="target", type=mac_address_to_bytes
    )

    args = parser.parse_args(args=argv)

    return typing.cast(str, args.target)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        format="%(filename)s: %(levelname)s: %(message)s", level=logging.INFO
    )
    target = parse_target_from_args(argv)
    send_magic_packet(target)


if __name__ == "__main__":
    main()
