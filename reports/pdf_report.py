import json
import os
import re
from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4


class PDFReportGenerator:

    def __init__(self, case_manager):
        self.case = case_manager
        self.evidence_dir = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

    def load(self, filename):
        path = os.path.join(
            self.evidence_dir,
            filename
        )
        if not os.path.exists(path):
            return {}
        with open(path, "r") as f:
            return json.load(f)

    def generate(self):
        # Load all evidence
        kernel = self.load("kernel_information.json")
        modules = self.load("kernel_modules.json")
        hidden_modules = self.load("hidden_modules.json")
        hidden_processes = self.load("hidden_processes.json")
        network = self.load("network_connections.json")
        logs = self.load("kernel_logs.json")
        hooks = self.load("kernel_hooks.json")
        persistence = self.load("persistence.json")
        baseline = self.load("baseline_comparison.json")
        mitre = self.load("mitre_mapping.json")
        correlation = self.load("correlation_findings.json")
        ioc = self.load("ioc_matches.json")
        integrity = self.load("integrity_verification.json")
        timeline = self.load("timeline.json")
        threat = self.load("threat_assessment.json")
        ai_analysis = self.load("ai_explanation.json")

        filename = f"reports/generated/AKRDFAS_{self.case.get_case_id()}.pdf"

        styles = getSampleStyleSheet()
        
        centered_style = ParagraphStyle(
            'Centered',
            parent=styles['BodyText'],
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'HeadingStyle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.darkblue,
            spaceAfter=6
        )
        
        section_heading_style = ParagraphStyle(
            'SectionHeadingStyle',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.darkblue,
            spaceAfter=6
        )
        
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['BodyText'],
            fontSize=10,
            spaceAfter=4
        )

        # Define common table style
        TABLE_STYLE = TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8)
        ])

        # Define table style for network connections
        NETWORK_TABLE_STYLE = TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])

        def add_footer(canvas, doc):
            canvas.saveState()
            canvas.setFont('Helvetica', 8)
            canvas.drawString(72, 30, f"AKRDFAS v1.0 | Case: {self.case.get_case_id()}")
            canvas.drawString(450, 30, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(filename, pagesize=A4)
        elements = []

        # -------------------------
        # CASE INFORMATION HEADER (Page 1)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>AKRDFAS</b>",
                styles["Title"]
            )
        )

        elements.append(
            Paragraph(
                "Advanced Linux Kernel Rootkit Detection and Forensic Analysis System",
                styles["Heading2"]
            )
        )

        elements.append(Spacer(1, 20))

        elements.append(
            Paragraph(
                "<b>Digital Forensic Investigation Report</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        # Case Information Header
        case_header_data = [
            ["Case ID:", self.case.get_case_id()],
            ["Hostname:", kernel.get("hostname", "-")],
            ["Kernel Version:", kernel.get("kernel_release", "-")],
            ["Operating System:", kernel.get("system", "-")],
            ["Generated On:", datetime.now().strftime("%d %B %Y %H:%M")],
            ["Investigator:", "AKRDFAS Automated System"],
            ["Version:", "AKRDFAS v1.0"]
        ]

        case_header = Table(case_header_data, colWidths=[150, 300])
        case_header.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9)
        ]))

        elements.append(case_header)
        elements.append(Spacer(1, 15))

        # -------------------------
        # THREAT SUMMARY BOX
        # -------------------------

        elements.append(
            Paragraph(
                "<b>THREAT SUMMARY</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        threat_score = threat.get('threat_score', 0)
        threat_level = threat.get('threat_level', 'LOW')
        hidden_mod_count = hidden_modules.get('summary', {}).get('discrepancies', 0)
        hidden_proc_count = hidden_processes.get('summary', {}).get('discrepancies', 0)
        suspicious_hooks = hooks.get("summary", {}).get("suspicious_hooks", 0)
        ioc_count = ioc.get('summary', {}).get('ioc_matches', 0)
        correlation_score = correlation.get('total_score', 0)

        # Color threat level
        if threat_level == "LOW":
            color = colors.green
        elif threat_level == "MEDIUM":
            color = colors.orange
        elif threat_level == "HIGH":
            color = colors.red
        else:
            color = colors.darkred

        threat_summary_data = [
            ["Metric", "Value"],
            ["Threat Score", f"{threat_score}/100"],
            ["Threat Level", f"<font color='{color.hexval()}'><b>{threat_level}</b></font>"],
            ["Hidden Modules", str(hidden_mod_count)],
            ["Hidden Processes", str(hidden_proc_count)],
            ["Kernel Hooks", str(suspicious_hooks)],
            ["IOC Matches", str(ioc_count)],
            ["Correlation Score", str(correlation_score)]
        ]

        threat_summary_table = Table(threat_summary_data, colWidths=[150, 150])
        threat_summary_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 1), (1, -1), "CENTER")
        ]))
        elements.append(threat_summary_table)
        elements.append(Spacer(1, 15))

        # -------------------------
        # FINDINGS SUMMARY TABLE
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Findings Summary</b>",
                styles["Heading2"]
            )
        )

        elements.append(Spacer(1, 10))

        findings_data = [
            ["Detector", "Status"],
            ["Kernel Modules", "PASS" if modules.get('findings') else "PASS"],
            ["Kernel Hooks", "PASS" if not suspicious_hooks else "WARNING"],
            ["Kernel Integrity", "PASS" if integrity.get('status') == "VERIFIED" else "FAIL"],
            ["Network Analysis", "PASS" if network.get('connections') else "PASS"],
            ["Persistence", "PASS" if not persistence.get('findings') else "WARNING"],
            ["Hidden Processes", "PASS" if not hidden_proc_count else "WARNING"],
            ["Hidden Modules", "PASS" if not hidden_mod_count else "WARNING"]
        ]

        findings_table = Table(findings_data, colWidths=[200, 150])
        findings_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 1), (1, -1), "CENTER")
        ]))

        # Color the status cells
        for i, row in enumerate(findings_data[1:], start=1):
            status = row[1]
            if status == "PASS":
                findings_table.setStyle(TableStyle([
                    ("TEXTCOLOR", (1, i), (1, i), colors.green)
                ]))
            elif status == "WARNING":
                findings_table.setStyle(TableStyle([
                    ("TEXTCOLOR", (1, i), (1, i), colors.orange)
                ]))
            elif status == "FAIL":
                findings_table.setStyle(TableStyle([
                    ("TEXTCOLOR", (1, i), (1, i), colors.red)
                ]))

        elements.append(findings_table)
        elements.append(Spacer(1, 15))


        # -------------------------
        # THREAT FINDINGS (Page 2)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Threat Findings</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        reasons = threat.get("reasons", [])
        if reasons:
            filtered_reasons = [r for r in reasons if not r.startswith("[CR-")]
            if filtered_reasons:
                for reason in filtered_reasons:
                    elements.append(
                        Paragraph(
                            f"• {reason}",
                            styles["BodyText"]
                        )
                    )
            else:
                elements.append(
                    Paragraph(
                        "No significant threat findings.",
                        styles["BodyText"]
                    )
                )
        else:
            elements.append(
                Paragraph(
                    "No significant threat findings.",
                    styles["BodyText"]
                )
            )

        elements.append(Spacer(1, 12))
        elements.append(PageBreak())

        # -------------------------
        # THREAT SCORE BREAKDOWN (Page 3)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Threat Score Breakdown</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        hook_points = min(suspicious_hooks * 10, 20)

        data = [
            ["Detection", "Findings", "Contribution"],
            [
                "Hidden Processes",
                hidden_processes.get("summary", {}).get("discrepancies", 0),
                "Dynamic"
            ],
            [
                "Hidden Modules",
                hidden_modules.get("summary", {}).get("discrepancies", 0),
                "Dynamic"
            ],
            [
                "Kernel Hooks",
                suspicious_hooks,
                f"+{hook_points}"
            ],
            [
                "Kernel Errors",
                logs.get("summary", {}).get("errors", 0),
                "Dynamic"
            ],
            [
                "Persistence",
                persistence.get("summary", {}).get("suspicious_entries", 0),
                "Dynamic"
            ],
            [
                "Correlation",
                correlation.get("total_score", 0),
                f"+{correlation.get('total_score', 0)}"
            ],
            [
                "IOC Matches",
                ioc.get("summary", {}).get("ioc_matches", 0),
                "Dynamic"
            ]
        ]

        table = Table(data)
        table.setStyle(TABLE_STYLE)
        elements.append(table)
        elements.append(Spacer(1, 12))
        elements.append(PageBreak())

        # -------------------------
        # AI INVESTIGATION ANALYSIS
        # -------------------------

        elements.append(
            Paragraph(
                "<b>AI Investigation Analysis</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        # Clean markdown from AI text
        ai_text = ai_analysis.get("analysis", "No AI analysis available.")
        
        # Remove markdown formatting
        ai_text = re.sub(r"^#+\s*", "", ai_text, flags=re.MULTILINE)
        ai_text = ai_text.replace("**", "")
        ai_text = ai_text.replace("__", "")
        ai_text = ai_text.replace("`", "")
        ai_text = ai_text.replace("---", "")
        ai_text = re.sub(r"```\w*", "", ai_text)
        ai_text = ai_text.replace("```", "")
        
        # Split into paragraphs and add properly
        paragraphs = ai_text.split("\n\n")
        
        for paragraph in paragraphs:
            lines = paragraph.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line:
                    # Check if it looks like a heading (all caps or short)
                    if len(line) < 60 and line.isupper():
                        elements.append(
                            Paragraph(
                                f"<b>{line}</b>",
                                section_heading_style
                            )
                        )
                    else:
                        elements.append(
                            Paragraph(
                                line,
                                body_style
                            )
                        )
                    elements.append(Spacer(1, 4))
            if len(paragraphs) > 1:
                elements.append(Spacer(1, 6))

        elements.append(Spacer(1, 15))
        elements.append(PageBreak())

        # -------------------------
        # EVIDENCE STATISTICS (Page 4)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Evidence Statistics</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        verified_count = len(integrity.get("verified", []))
        tampered_count = len(integrity.get("tampered", []))
        timeline_events = len(timeline.get("events", []))
        mitre_count = mitre.get("summary", {}).get("techniques_detected", 0)
        correlation_count = len(correlation.get("findings", []))

        data = [
            ["Statistic", "Value"],
            ["Verified Files", verified_count],
            ["Tampered Files", tampered_count],
            ["Timeline Events", timeline_events],
            ["MITRE Techniques", mitre_count],
            ["IOC Matches", ioc_count],
            ["Correlation Rules", correlation_count]
        ]

        table = Table(data)
        table.setStyle(TABLE_STYLE)
        elements.append(table)
        elements.append(Spacer(1, 15))
        elements.append(PageBreak())

        # -------------------------
        # CASE INFORMATION (Page 5)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Case Information</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        case_details = Table([
            ["Case ID:", self.case.get_case_id()],
            ["Investigation Date:", datetime.now().strftime("%d %B %Y %H:%M")],
            ["Hostname:", kernel.get("hostname", "-")],
            ["Operating System:", kernel.get("system", "-")],
            ["Kernel Version:", kernel.get("kernel_release", "-")],
            ["Architecture:", kernel.get("architecture", "-")],
            ["Uptime:", f"{kernel.get('uptime_seconds', 0)} seconds"],
            ["Evidence Directory:", self.evidence_dir],
            ["Generated By:", "AKRDFAS v1.0"]
        ])

        case_details.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
        ]))

        elements.append(case_details)
        elements.append(PageBreak())

        # -------------------------
        # KERNEL MODULE EVIDENCE (Page 6)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Kernel Module Evidence</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        findings = modules.get("findings", [])
        high_medium = [
            m for m in findings
            if m.get("risk", {}).get("level") in ["HIGH", "MEDIUM"]
        ]

        display_modules = high_medium if high_medium else findings[:10]

        if display_modules:
            for module in display_modules:
                risk = module.get("risk", {})
                reasons_list = risk.get("reasons", [])
                reasons = "<br/>".join(reasons_list) if reasons_list else "None"
                deps = ", ".join(module.get("dependencies", [])) or "-"

                elements.append(
                    Paragraph(
                        f"<b>{module.get('name', 'Unknown')}</b>",
                        styles["Heading3"]
                    )
                )

                module_data = [
                    ["Risk", risk.get("level", "LOW")],
                    ["Score", str(risk.get("score", 0))],
                    ["Path", module.get("path", "-")],
                    ["Description", module.get("description") or "-"],
                    ["Author", module.get("author") or "-"],
                    ["License", module.get("license") or "-"],
                    ["Dependencies", deps],
                    ["SHA256", module.get("sha256", "-")],
                    ["Risk Reasons", reasons]
                ]

                table = Table(module_data, colWidths=[120, 350])
                table.setStyle(TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8)
                ]))
                elements.append(table)
                elements.append(Spacer(1, 12))
        else:
            elements.append(
                Paragraph(
                    "No kernel modules with HIGH/MEDIUM risk detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # HIDDEN KERNEL MODULES (Page 7)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Hidden Kernel Modules</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        hidden = hidden_modules.get("hidden_modules", [])
        if hidden:
            data = [["Module"]]
            for module in hidden:
                data.append([module])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No hidden kernel modules detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # HIDDEN PROCESSES (Page 8)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Hidden Processes</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        findings = hidden_processes.get("findings", [])
        if findings:
            data = [["PID", "Process", "Reason"]]
            for process in findings:
                data.append([
                    process.get("pid", "-"),
                    process.get("name", "-"),
                    process.get("reason", "-")
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No hidden processes detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # KERNEL HOOK FINDINGS (Page 9)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Kernel Hook Findings</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        findings = hooks.get("findings", [])
        if findings:
            data = [["Severity", "Finding"]]
            for finding in findings:
                severity = finding.get("severity")
                if not severity:
                    severity = finding.get("type", "INFO")
                data.append([
                    severity,
                    finding.get("message", finding.get("value", ""))
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No suspicious kernel hooks detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # KERNEL LOG FINDINGS (Page 10)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Kernel Log Findings</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        entries = logs.get("findings", [])
        if entries:
            data = [["Severity", "Message"]]
            for entry in entries:
                data.append([
                    entry.get("type", "-"),
                    entry.get("message", "-")
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No suspicious kernel log entries detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # NETWORK CONNECTIONS (Page 11) 
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Network Connections</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        connections = network.get("connections", [])
        if connections:
            display_connections = connections[:50]
            col_widths = [80, 40, 120, 120, 70]

            data = [
                ["Process", "PID", "Local", "Remote", "Status"]
            ]
            for conn in display_connections:
                process = conn.get("process") or "-"
                if len(process) > 20:
                    process = process[:17] + "..."

                local = conn.get("local", "-")
                if len(local) > 25:
                    local = local[:22] + "..."

                remote = conn.get("remote", "-")
                if len(remote) > 25:
                    remote = remote[:22] + "..."

                status = conn.get("status", "-")
                if len(status) > 15:
                    status = status[:12] + "..."

                data.append([
                    process,
                    str(conn.get("pid") or "-"),
                    local,
                    remote,
                    status
                ])

            table = Table(data, colWidths=col_widths)
            table.setStyle(NETWORK_TABLE_STYLE)
            elements.append(table)

            if len(connections) > 50:
                elements.append(
                    Paragraph(
                        f"<i>Showing first 50 of {len(connections)} connections.</i>",
                        styles["BodyText"]
                    )
                )
        else:
            elements.append(
                Paragraph(
                    "No active network connections detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # PERSISTENCE ARTIFACTS (Page 12)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Persistence Artifacts</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        persistence_entries = persistence.get("findings", [])
        if persistence_entries:
            data = [["Type", "Path", "Severity"]]
            for entry in persistence_entries[:50]:
                path = entry.get("path", "-")
                if len(path) > 40:
                    path = path[:37] + "..."
                data.append([
                    entry.get("type", "-"),
                    path,
                    entry.get("severity", "-")
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No persistence artifacts detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # MITRE ATT&CK MAPPING (Page 13)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>MITRE ATT&CK Mapping</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        techniques = mitre.get("techniques", [])
        if techniques:
            data = [
                ["Technique", "Name", "Severity", "Evidence"]
            ]
            for t in techniques:
                evidence = t.get("reason", "-")
                if len(evidence) > 30:
                    evidence = evidence[:27] + "..."
                data.append([
                    t.get("id", "-"),
                    t.get("name", "-"),
                    t.get("severity", "-"),
                    evidence
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No MITRE techniques identified.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # IOC MATCHES (Page 14)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>IOC Matches</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        matches = ioc.get("findings", [])
        if matches:
            data = [
                ["Indicator", "Severity", "Description"]
            ]
            for finding in matches[:50]:
                indicator = finding.get("indicator", "-")
                if len(indicator) > 25:
                    indicator = indicator[:22] + "..."
                description = finding.get("description", "-")
                if len(description) > 30:
                    description = description[:27] + "..."
                data.append([
                    indicator,
                    finding.get("severity", "-"),
                    description
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No Indicators of Compromise detected.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # CORRELATION FINDINGS (Page 15)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Correlation Findings</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        findings = correlation.get("findings", [])
        if findings:
            data = [
                ["Rule", "Severity", "Description"]
            ]
            for rule in findings[:50]:
                desc = rule.get("description", "-")
                if len(desc) > 30:
                    desc = desc[:27] + "..."
                data.append([
                    rule.get("rule", "-"),
                    rule.get("severity", "-"),
                    desc
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No correlation rules matched.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # EVIDENCE INTEGRITY (Page 16)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Evidence Integrity</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        data = [["Evidence File", "Status"]]
        for file in integrity.get("verified", []):
            data.append([file, "VERIFIED"])
        for file in integrity.get("tampered", []):
            data.append([file, "TAMPERED"])

        if len(data) == 1:
            data.append(["-", "No Evidence Files"])

        table = Table(data)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8)
        ]))
        elements.append(table)
        elements.append(PageBreak())

        # -------------------------
        # INVESTIGATION TIMELINE (Page 17)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Investigation Timeline</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        events = timeline.get("events", [])
        if events:
            data = [["Time", "Event"]]
            for event in events:
                data.append([
                    event.get("time", "-"),
                    event.get("event", "-")
                ])
            table = Table(data)
            table.setStyle(TABLE_STYLE)
            elements.append(table)
        else:
            elements.append(
                Paragraph(
                    "No timeline information available.",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # EVIDENCE INVENTORY (Page 18)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Evidence Inventory</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        descriptions = {
            "kernel_information.json": "Kernel Information",
            "kernel_baseline.json": "Trusted Baseline",
            "kernel_modules.json": "Kernel Modules",
            "hidden_modules.json": "Hidden Modules",
            "hidden_processes.json": "Hidden Processes",
            "kernel_integrity.json": "Kernel Integrity",
            "network_connections.json": "Network Connections",
            "persistence.json": "Persistence",
            "kernel_hooks.json": "Kernel Hooks",
            "kernel_logs.json": "Kernel Logs",
            "baseline_comparison.json": "Baseline Comparison",
            "correlation_findings.json": "Correlation Findings",
            "mitre_mapping.json": "MITRE Mapping",
            "ioc_matches.json": "IOC Matches",
            "integrity_verification.json": "Evidence Integrity",
            "timeline.json": "Investigation Timeline",
            "threat_assessment.json": "Threat Assessment",
            "ai_explanation.json": "AI Analysis"
        }

        inventory_data = [["Evidence File", "Description"]]
        for file, desc in descriptions.items():
            if os.path.exists(os.path.join(self.evidence_dir, file)):
                inventory_data.append([file, desc])

        table = Table(inventory_data)
        table.setStyle(TABLE_STYLE)
        elements.append(table)
        elements.append(PageBreak())

        # -------------------------
        # RECOMMENDED INVESTIGATION ACTIONS (Page 19)
        # -------------------------

        elements.append(
            Paragraph(
                "<b>Recommended Investigation Actions</b>",
                styles["Heading1"]
            )
        )

        elements.append(Spacer(1, 10))

        actions = [
            "Review suspicious kernel hook findings.",
            "Validate loaded kernel modules.",
            "Inspect kernel logs.",
            "Compare against trusted baseline.",
            "Preserve all collected evidence."
        ]

        for action in actions:
            elements.append(
                Paragraph(
                    f"• {action}",
                    styles["BodyText"]
                )
            )

        elements.append(PageBreak())

        # -------------------------
        # FINAL VERDICT PAGE (Page 20)
        # -------------------------

        elements.append(Spacer(1, 50))

        elements.append(
            Paragraph(
                "<b>FINAL ASSESSMENT</b>",
                styles["Title"]
            )
        )

        elements.append(Spacer(1, 30))

        elements.append(
            Paragraph(
                "<b>Threat Level</b>",
                styles["Heading2"]
            )
        )

        if threat_level == "LOW":
            color = colors.green
        elif threat_level == "MEDIUM":
            color = colors.orange
        elif threat_level == "HIGH":
            color = colors.red
        else:
            color = colors.darkred

        elements.append(
            Paragraph(
                f"<font color='{color.hexval()}' size='20'><b>{threat_level}</b></font>",
                centered_style
            )
        )

        elements.append(Spacer(1, 20))

        elements.append(
            Paragraph(
                "<b>System Integrity</b>",
                styles["Heading2"]
            )
        )

        integrity_status = integrity.get('status', 'UNKNOWN')
        if integrity_status == "VERIFIED":
            status_color = colors.green
        else:
            status_color = colors.red

        elements.append(
            Paragraph(
                f"<font color='{status_color.hexval()}' size='16'><b>{integrity_status}</b></font>",
                centered_style
            )
        )

        elements.append(Spacer(1, 20))

        elements.append(
            Paragraph(
                "<b>Recommendation</b>",
                styles["Heading2"]
            )
        )

        if threat_level == "LOW" and integrity_status == "VERIFIED":
            recommendation = "Continue monitoring."
        elif threat_level == "MEDIUM":
            recommendation = "Investigate suspicious findings and review logs."
        elif threat_level == "HIGH":
            recommendation = "Immediate incident response required."
        else:
            recommendation = "Further investigation recommended."

        elements.append(
            Paragraph(
                recommendation,
                centered_style
            )
        )

        elements.append(Spacer(1, 40))

        elements.append(
            Paragraph(
                "Generated by AKRDFAS",
                centered_style
            )
        )

        elements.append(
            Paragraph(
                "Advanced Linux Kernel Rootkit Detection and Forensic Analysis System",
                centered_style
            )
        )

        elements.append(Spacer(1, 10))

        elements.append(
            Paragraph(
                f"Case ID: {self.case.get_case_id()}",
                centered_style
            )
        )

        elements.append(
            Paragraph(
                datetime.now().strftime("%d %B %Y %H:%M"),
                centered_style
            )
        )

        # Build the PDF with footer
        doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
        print("[✓] PDF Report Generated")