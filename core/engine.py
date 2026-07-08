from core.evidence_manager import EvidenceManager
from modules.kernel.kernel_information_detector import KernelInformationDetector
from modules.kernel.kernel_baseline_detector import KernelBaselineDetector
from modules.kernel.module_detector import KernelModuleDetector
from modules.kernel.hidden_module_detector import HiddenModuleDetector
from modules.kernel.hidden_process_detector import HiddenProcessDetector
from modules.kernel.kernel_integrity_detector import KernelIntegrityDetector
from modules.network.network_detector import NetworkDetector
from core.threat_engine import ThreatCorrelationEngine
from reports.html_report import HTMLReportGenerator
from reports.pdf_report import PDFReportGenerator
from modules.kernel.persistence_detector import PersistenceDetector
from modules.kernel.kernel_log_detector import KernelLogDetector
from modules.kernel.kernel_hook_detector import KernelHookDetector
from core.integrity_verifier import IntegrityVerifier
from core.baseline_comparator import BaselineComparator
from core.baseline_creator import BaselineCreator
from core.correlation_engine import CorrelationEngine
from core.mitre_mapper import MitreMapper
from core.timeline_logger import TimelineLogger
from modules.ioc.ioc_detector import IOCDetector

class DetectionEngine:

    def __init__(self, logger, case_manager):
        self.logger = logger
        self.case = case_manager
        self.evidence = EvidenceManager(case_manager)

    def run(self):
        self.logger.info("Starting Detection Engine")

        timeline = TimelineLogger(self.case)

        # ------------------------------------
        # Investigation Started
        # ------------------------------------
        timeline.add_event("Investigation Started")
        timeline.save()

        # ------------------------------------
        # Kernel Information
        # ------------------------------------
        information = KernelInformationDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelInformationDetector")
        information.run()
        timeline.add_event("Kernel Information Collected")
        timeline.save()

        # ------------------------------------
        # Kernel Baseline
        # ------------------------------------
        baseline = KernelBaselineDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelBaselineDetector")
        baseline.run()
        timeline.add_event("Kernel Baseline Collected")
        timeline.save()

        # ------------------------------------
        # Kernel Module Detection
        # ------------------------------------
        modules = KernelModuleDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelModuleDetector")
        modules.run()
        timeline.add_event("Kernel Modules Analyzed")
        timeline.save()

        # ------------------------------------
        # Hidden Module Detection
        # ------------------------------------
        hidden = HiddenModuleDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("HiddenModuleDetector")
        hidden.run()
        timeline.add_event("Hidden Module Detection Completed")
        timeline.save()

        # ------------------------------------
        # Hidden Process Detection
        # ------------------------------------
        process = HiddenProcessDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("HiddenProcessDetector")
        process.run()
        timeline.add_event("Hidden Process Detection Completed")
        timeline.save()

        # ------------------------------------
        # Kernel Integrity Detection
        # ------------------------------------
        integrity = KernelIntegrityDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelIntegrityDetector")
        integrity.run()
        timeline.add_event("Kernel Integrity Checked")
        timeline.save()

        # ------------------------------------
        # Network Detection
        # ------------------------------------
        network = NetworkDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("NetworkDetector")
        network.run()
        timeline.add_event("Network Analysis Completed")
        timeline.save()

        # ------------------------------------
        # Baseline Creator
        # ------------------------------------
        creator = BaselineCreator(self.case)
        self.case.register_detector("BaselineCreator")
        creator.run()
        timeline.add_event("Trusted Baseline Verified")
        timeline.save()

        # ------------------------------------
        # Persistence Detection
        # ------------------------------------
        persistence = PersistenceDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("PersistenceDetector")
        persistence.run()
        timeline.add_event("Persistence Analysis Completed")
        timeline.save()

        # ------------------------------------
        # Kernel Hook Detection
        # ------------------------------------
        hook_detector = KernelHookDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelHookDetector")
        hook_detector.run()
        timeline.add_event("Kernel Hook Detection Completed")
        timeline.save()

        # ------------------------------------
        # Kernel Log Analysis
        # ------------------------------------
        logs = KernelLogDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("KernelLogDetector")
        logs.run()
        timeline.add_event("Kernel Log Analysis Completed")
        timeline.save()

        # ------------------------------------
        # Baseline Comparator
        # ------------------------------------
        comparator = BaselineComparator(self.case)
        comparator.run()
        timeline.add_event("Baseline Comparison Completed")
        timeline.save()

        # ------------------------------------
        # Correlation Engine
        # ------------------------------------
        correlation = CorrelationEngine(self.case)
        correlation.run()
        timeline.add_event("Threat Correlation Completed")
        timeline.save()

        # ------------------------------------
        # MITRE ATT&CK Mapping
        # ------------------------------------
        mitre = MitreMapper(self.case)
        mitre.run()
        timeline.add_event("MITRE ATT&CK Mapping Completed")
        timeline.save()

        # ------------------------------------
        # IOC Detection
        # ------------------------------------
        ioc = IOCDetector(
            self.logger,
            self.evidence,
            self.case
        )
        self.case.register_detector("IOCDetector")
        ioc.run()
        timeline.add_event("IOC Scan Completed")
        timeline.save()

        # ------------------------------------
        # Threat Correlation Engine
        # ------------------------------------
        threat = ThreatCorrelationEngine(self.case)
        threat.run()
        timeline.add_event("Threat Assessment Completed")
        timeline.save()

        # ------------------------------------
        # Integrity Verification
        # ------------------------------------
        verifier = IntegrityVerifier(self.case)
        verifier.run()
        timeline.add_event("Evidence Integrity Verified")
        timeline.save()

        # ------------------------------------
        # Timeline Finalization Before Reports
        # ------------------------------------
        timeline.add_event("Preparing HTML Report")
        timeline.save()

        # ------------------------------------
        # Generate HTML Report
        # ------------------------------------
        html_report = HTMLReportGenerator(self.case)
        html_report.generate()
        timeline.add_event("HTML Report Generated")
        timeline.save()

        # ------------------------------------
        # Generate PDF Report
        # ------------------------------------
        timeline.add_event("Preparing PDF Report")
        timeline.save()

        pdf_report = PDFReportGenerator(self.case)
        pdf_report.generate()
        timeline.add_event("PDF Report Generated")
        timeline.save()

        # ------------------------------------
        # Investigation Completed
        # ------------------------------------
        timeline.add_event("Investigation Completed")
        timeline.save()

        # ------------------------------------
        # Close Investigation
        # ------------------------------------
        self.case.close_case()

        self.logger.info("Detection Engine Finished")
