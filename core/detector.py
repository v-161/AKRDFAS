from abc import ABC, abstractmethod


class BaseDetector(ABC):

    def __init__(
        self,
        logger,
        evidence_manager,
        case_manager
    ):

        self.logger = logger

        self.evidence = evidence_manager

        self.case = case_manager

    @abstractmethod
    def run(self):

        pass