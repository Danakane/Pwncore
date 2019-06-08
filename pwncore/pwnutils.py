import typing


class Architecture:

    def __init__(self, littleendian: str, bigendian: str, network: str, size: int):
        self.__littleendian__: str = "<" + littleendian
        self.__bigendian__: str = ">" + bigendian
        self.__network__: str = "!" + network
        self.__size__: int = size

    @property
    def littleendian(self) -> str:
        return self.__littleendian__

    @property
    def bigendian(self) -> str:
        return self.__bigendian__

    @property
    def size(self) -> int:
        return self.__size__


class X64(Architecture):

    def __init__(self):
        Architecture.__init__(self, "Q", "Q", "Q", 8)


class X86(Architecture):

    def __init__(self):
        Architecture.__init__(self, "I", "I", "I", 4)


def addressformat(addr: str, maxaddr: str = "") -> str:
    splits: typing.List[str] = addr.split("x")
    formattedaddr: str = splits[0]
    if len(splits) > 1:
        formattedaddr = splits[1]
    formattedaddr = formattedaddr.lstrip("0")
    if formattedaddr == "":
        formattedaddr = "0"
    formattedaddr = "0" * (len(maxaddr.lstrip("0x")) - len(formattedaddr)) + formattedaddr
    return "0x" + formattedaddr
