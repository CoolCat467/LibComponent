"""Shared network code."""

# Programmed by CoolCat467

from __future__ import annotations

# Copyright (C) 2023-2024  CoolCat467
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__title__ = "Network Utilities"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"


import time

import trio

from libcomponent.buffer import Buffer
from libcomponent.component import Event
from libcomponent.encrypted_network import EncryptedNetworkEventComponent
from libcomponent.encryption import (
    RSAPrivateKey,
    decrypt_token_and_secret,
    deserialize_public_key,
    encrypt_token_and_secret,
    generate_rsa_key,
    generate_shared_secret,
    generate_verify_token,
    serialize_public_key,
)

# Stolen from WOOF (Web Offer One File), Copyright (C) 2004-2009 Simon Budig,
# available at http://www.home.unix-ag.org/simon/woof
# with modifications

# Utility function to guess the IP (as a string) where the server can be
# reached from the outside. Quite nasty problem actually.


async def find_ip() -> str:  # pragma: nocover
    """Guess the IP where the server can be found from the network."""
    # we get a UDP-socket for the TEST-networks reserved by IANA.
    # It is highly unlikely, that there is special routing used
    # for these networks, hence the socket later should give us
    # the IP address of the default route.
    # We're doing multiple tests, to guard against the computer being
    # part of a test installation.

    candidates: list[str] = []
    for test_ip in ("192.0.2.0", "198.51.100.0", "203.0.113.0"):
        sock = trio.socket.socket(trio.socket.AF_INET, trio.socket.SOCK_DGRAM)
        await sock.connect((test_ip, 80))
        ip_addr: str = sock.getsockname()[0]
        sock.close()
        if ip_addr in candidates:
            return ip_addr
        candidates.append(ip_addr)

    return candidates[0]


class ServerClientNetworkEventComponent(EncryptedNetworkEventComponent):
    """Server Client Network Event Component.

    When clients connect to server, this class handles the incoming
    connections to the server in the way of reading and raising events
    that are transferred over the network.
    """

    __slots__ = ("rsa_key", "verify_token")

    def __init__(self, name: str) -> None:
        """Initialize Server Client."""
        super().__init__(name)

        self.rsa_key: RSAPrivateKey | None = None
        self.verify_token: bytes | None = None

    async def write_callback_ping(self) -> None:
        """Write callback_ping packet to client.

        Writes `server[write]->callback_ping` event.

        Could raise the following exceptions:
          trio.BrokenResourceError: if something has gone wrong, and the stream
            is broken.
          trio.ClosedResourceError: if stream was previously closed

        Listed as possible but probably not because of write lock:
          trio.BusyResourceError: if another task is using :meth:`write`
        """

        # Try to be as accurate with time as possible
        def time_data_function() -> bytearray:
            buffer = Buffer()
            ns = int(time.time() * 1e9)
            # Use as many bits as time needs, write_buffer handles size for us.
            buffer.write(ns.to_bytes(-(-ns.bit_length() // 8), "big"))
            return buffer

        await self.write_event_last_minute_data(
            "server[write]->callback_ping",
            time_data_function,
        )

    async def start_encryption_request(self) -> None:
        """Start encryption request and raise as `server[write]->encryption_request`.

        Make sure to read an event and send it to `handle_encryption_response` immediately after
        calling this function.
        """
        if self.encryption_enabled:
            raise RuntimeError("Encryption is already set up!")
        self.rsa_key = generate_rsa_key()
        self.verify_token = generate_verify_token()

        public_key = self.rsa_key.public_key()

        serialized_public_key = serialize_public_key(public_key)

        buffer = Buffer()
        buffer.write_bytearray(serialized_public_key)
        buffer.write_bytearray(self.verify_token)

        await self.write_event(
            Event("server[write]->encryption_request", buffer),
        )

    async def handle_encryption_response(
        self,
        event: Event[bytearray],
    ) -> None:
        """Read encryption response event data.

        Sets up socket stream to use encryption for all future interactions.
        """
        if self.rsa_key is None or self.verify_token is None:
            raise RuntimeError(
                "Was not expecting encryption response, request start not sent!",
            )
        if self.encryption_enabled:
            raise RuntimeError("Encryption is already set up!")
        buffer = Buffer(event.data)

        encrypted_shared_secret = buffer.read_bytearray()
        encrypted_verify_token = buffer.read_bytearray()

        verify_token, shared_secret = decrypt_token_and_secret(
            self.rsa_key,
            encrypted_verify_token,
            encrypted_shared_secret,
        )

        if verify_token != self.verify_token:
            raise RuntimeError(
                "Received verify token does not match sent verify token!",
            )

        # Start encrypting all future data
        self.enable_encryption(shared_secret, verify_token)


class ClientNetworkEventComponent(EncryptedNetworkEventComponent):
    """Client Network Event Component.

    This class handles connecting to the game server, transmitting events
    to the server, and reading and raising incoming events from the server.
    """

    async def read_callback_ping(self, event: Event[bytearray]) -> None:
        """Read callback_ping event from server.

        Raises `callback_ping` with number of nanoseconds (int) of delay
        in network connection.
        """
        ns = int.from_bytes(event.data)
        now = int(time.time() * 1e9)
        difference = now - ns

        # print(f'{difference / 1e9 = } seconds')

        await self.raise_event(
            Event("callback_ping", difference),
        )

    async def write_encryption_response(
        self,
        shared_secret: bytes,
        verify_token: bytes,
    ) -> None:
        """Write encryption response to server.

        Writes `encryption_response->server` event.
        """
        buffer = Buffer()
        buffer.write_bytearray(shared_secret)
        buffer.write_bytearray(verify_token)

        await self.write_event(Event("encryption_response->server", buffer))

    async def read_encryption_request(self, event: Event[bytearray]) -> None:
        """Read and handle encryption request from server.

        Writes `encryption_response->server` event.

        Sets up socket stream to use encryption for all future interactions.
        """
        buffer = Buffer(event.data)

        serialized_public_key = buffer.read_bytearray()
        verify_token = buffer.read_bytearray()

        public_key = deserialize_public_key(serialized_public_key)

        shared_secret = generate_shared_secret()

        encrypted_token, encrypted_secret = encrypt_token_and_secret(
            public_key,
            verify_token,
            shared_secret,
        )

        await self.write_encryption_response(encrypted_secret, encrypted_token)

        # Start encrypting all future data
        self.enable_encryption(shared_secret, verify_token)
