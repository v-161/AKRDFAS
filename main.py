from core.config import Config
from core.logger import Logger
from core.case_manager import CaseManager
from core.engine import DetectionEngine

def main():

    config = Config()

    logger = Logger(config)

    case = CaseManager(config)

    print("=" * 60)
    print(config.get("project", "name"))
    print("Version:", config.get("project", "version"))
    print("=" * 60)

    print("Case ID :", case.get_case_id())
    print()

    engine = DetectionEngine(logger, case)

    engine.run()

    with open("scan_complete.flag", "w") as f:
        f.write("completed")

    print()
    print("Evidence stored in:")
    print(case.get_case_directory())


if __name__ == "__main__":
    main()
