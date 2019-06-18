import typing
import struct
from abc import ABCMeta

from pytoolcore import style
from pwncore import pwnutils


class ROPChainElement:
    __metaclass__ = ABCMeta

    def __init__(self, raw: bytes, elements: typing.List[str]):
        self.__raw__ = raw
        self.__elements__: typing.List[str] = elements

    @property
    def raw(self) -> bytes:
        return self.__raw__

    @property
    def elements(self) -> typing.List[str]:
        return self.__elements__


class Gadget:

    def __init__(self, gadgetname: str, gadgetaddr: int, base: int = 0x0, nbparameters: int = 0,
                 architecture: pwnutils.Architecture = pwnutils.Architecture,
                 gadgetcomments: str = "") -> None:
        self.__gadgetname__: str = gadgetname
        self.__gadgetaddr__: int = gadgetaddr
        self.__base__: int = base
        self.__gadgetcomments__: str = gadgetcomments
        self.__architecture__: pwnutils.Architecture = architecture
        self.__nbparameters__: int = nbparameters


class GadgetInstance(ROPChainElement):

    def __init__(self, gadget: Gadget, parameters: typing.List[int]) -> None:
        self.__gadgetname__ = gadget.__gadgetname__
        self.__gadgetaddr__: int = gadget.__gadgetaddr__
        self.__base__: int = gadget.__base__
        self.__architecture__: pwnutils.Architecture = gadget.__architecture__
        elements: typing.List[str] = []
        raw: bytes = struct.pack(self.__architecture__.littleendian, self.__base__ + self.__gadgetaddr__)
        elements.append("0x" + struct.pack(self.__architecture__.bigendian, self.__base__ + self.__gadgetaddr__).hex())
        if gadget.__nbparameters__ > 0:
            for parameter in parameters:
                raw += struct.pack(self.__architecture__.littleendian, parameter)
                elements.append("0x" + struct.pack(self.__architecture__.bigendian, parameter).hex())
        ROPChainElement.__init__(self, raw=raw, elements=elements)


class StackElement(ROPChainElement):

    def __init__(self, value: int,  architecture: pwnutils.Architecture):
        self.__value__: int = value
        self.__architecture__: pwnutils.Architecture = architecture
        elements: typing.List[str] = ["0x" + struct.pack(self.__architecture__.bigendian, self.__value__).hex()]
        ROPChainElement.__init__(self, raw=struct.pack(self.__architecture__.littleendian, self.__value__),
                                 elements=elements)

    @property
    def elements(self) -> typing.List[str]:
        return self.__elements__


class ROP:

    def __init__(self, base: int = 0, architecture: pwnutils.Architecture = pwnutils.X64()) -> None:
        self.__ropchain__: typing.List[ROPChainElement] = []
        self.__gadgets__: typing.Dict[str, Gadget] = {}
        self.__architecture__: pwnutils.Architecture = architecture
        self.__base__: int = base

    @property
    def base(self) -> int:
        return self.__base__

    @property
    def chain(self) -> typing.List[ROPChainElement]:
        return self.__ropchain__

    @property
    def raw(self) -> bytes:
        binary: bytes = b""
        for ropelement in self.__ropchain__:
            binary += ropelement.raw
        return binary

    def register(self, gadgetname: str, gadgetaddr: int, nbparameters: int, gadgetcomments: str = "") -> None:
        try:
            self.remove(gadgetname)
        except KeyError:
            pass
        self.__gadgets__[gadgetname] = Gadget(gadgetname, gadgetaddr, self.__base__, nbparameters,
                                              self.__architecture__, gadgetcomments)

    def remove(self, gadgetname) -> None:
        del self.__gadgets__[gadgetname]

    def __getitem__(self, gadgetname: str) -> Gadget:
        return self.__gadgets__[gadgetname]

    def packgadget(self, gadgetname: str, *parameters: int) -> None:
        self.__ropchain__.append(GadgetInstance(self.__gadgets__[gadgetname], list(parameters)))

    def pack(self, addr: int):
        self.__ropchain__.append(StackElement(addr, self.__architecture__))

    def clear(self, base: int = 0) -> None:
        self.__ropchain__ = []
        self.__base__ = base

    def dump(self, stackaddress: int = 0) -> str:
        rawaddress: int = stackaddress
        headers: typing.List[str] = ["Offset", "Value"]
        stack: typing.List[typing.List[str]] = []
        elements: typing.List[str] = []
        for ropelement in self.__ropchain__:
            elements += ropelement.elements
        maxaddr: str = pwnutils.addressformat(struct.pack(
            self.__architecture__.bigendian, stackaddress + self.__architecture__.size * (len(elements)-1)).hex())
        for element in elements:
            addr: str = pwnutils.addressformat(struct.pack(self.__architecture__.bigendian, rawaddress).hex(), maxaddr)
            rawaddress += self.__architecture__.size
            stack.append([addr, element])
        return style.Style.tabulate(headers, stack)
