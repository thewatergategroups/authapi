from enum import StrEnum


class Status(StrEnum):
    IN_PROGRESS = "inprogress"
    COMPLETED = "completed"
    FAILED = "failed"
