from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    FINDINGS = 1
    INVALID_USAGE = 2
    INTERNAL_ERROR = 3
