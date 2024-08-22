class CliException(Exception):
    """CLI Exception"""


class CmdException(Exception):
    """Exception for low-level commands"""


class FwException(Exception):
    """Exception for firmware parsing"""


class DeviceException(Exception):
    """Exception for device operations"""
