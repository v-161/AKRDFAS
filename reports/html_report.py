import os
import json
from datetime import datetime


class HTMLReportGenerator:

    def __init__(self, case_manager):

        self.case = case_manager

        self.case_dir = self.case.get_case_directory()

        self.evidence_dir = os.path.join(
            self.case_dir,
            "evidence"
        )

        self.output_dir = "reports/generated"

        os.makedirs(
            self.output_dir,
            exist_ok=True
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

    def load_ai_analysis(self):

        path = os.path.join(
            self.case.get_case_directory(),
            "evidence",
            "ai_explanation.json"
        )

        if not os.path.exists(path):
            return ""

        with open(path, "r") as file:
            data = json.load(file)

        return data.get("analysis", "")

    def generate(self):

        # -------------------------
        # Load Evidence
        # -------------------------

        kernel = self.load("kernel_information.json")

        baseline = self.load("kernel_baseline.json")

        baseline_compare = self.load("baseline_comparison.json")

        modules = self.load("kernel_modules.json")

        hidden_modules = self.load("hidden_modules.json")

        hidden_processes = self.load("hidden_processes.json")

        integrity = self.load("kernel_integrity.json")

        network = self.load("network_connections.json")

        logs = self.load("kernel_logs.json")

        hooks = self.load("kernel_hooks.json")

        persistence = self.load("persistence.json")

        threat = self.load("threat_assessment.json")

        mitre = self.load("mitre_mapping.json")

        correlation = self.load("correlation_findings.json")

        ioc = self.load("ioc_matches.json")

        integrity_report = self.load("integrity_verification.json")

        timeline = self.load("timeline.json")

        ai_analysis = self.load_ai_analysis()

        # -------------------------
        # Load CSS
        # -------------------------

        css = ""

        css_path = os.path.join(
            "reports",
            "templates",
            "style.css"
        )

        if os.path.exists(css_path):
            with open(css_path, "r") as f:
                css = f.read()

        # -------------------------
        # Kernel Module Summary
        # -------------------------

        module_summary = modules.get("summary", {})

        module_summary_html = f"""

        <table>

        <tr>

        <th>Total Modules</th>

        <th>High Risk</th>

        <th>Medium Risk</th>

        <th>Low Risk</th>

        </tr>

        <tr>

        <td>{module_summary.get("modules_scanned",0)}</td>

        <td>{module_summary.get("high_risk",0)}</td>

        <td>{module_summary.get("medium_risk",0)}</td>

        <td>{module_summary.get("low_risk",0)}</td>

        </tr>

        </table>

        """

        # -------------------------
        # Top Kernel Modules
        # -------------------------

        findings = modules.get("findings", [])

        findings = sorted(
            findings,
            key=lambda x: x.get("risk", {}).get("score", 0),
            reverse=True
        )

        module_table_html = """

        <table>

        <tr>

        <th>Name</th>

        <th>Risk</th>

        <th>Score</th>

        <th>Author</th>

        <th>License</th>

        <th>SHA256</th>

        </tr>

        """

        for module in findings[:10]:

            risk = module.get("risk", {})

            sha = module.get("sha256", "-")

            if len(sha) > 16:
                sha = sha[:16] + "..."

            module_table_html += f"""

            <tr>

            <td>{module.get("name","-")}</td>

            <td>{risk.get("level","-")}</td>

            <td>{risk.get("score",0)}</td>

            <td>{module.get("author") or "-"}</td>

            <td>{module.get("license") or "-"}</td>

            <td>{sha}</td>

            </tr>

            """

        module_table_html += "</table>"

        # -------------------------
        # Kernel Module Evidence (Detailed)
        # -------------------------

        findings = modules.get("findings", [])

        high_medium = [
            m for m in findings
            if m.get("risk", {}).get("level") in ["HIGH", "MEDIUM"]
        ]

        if high_medium:
            display_modules = high_medium
            note = ""
        else:
            display_modules = findings[:10]
            note = """
            <p><i>Showing first 10 modules because no suspicious modules were detected.</i></p>
            """

        module_evidence_html = note

        module_evidence_html += """

        <table>

        <tr>

        <th>Module</th>
        <th>Risk</th>
        <th>Score</th>
        <th>Author</th>
        <th>License</th>

        </tr>

        """

        for module in display_modules:

            risk = module.get("risk", {})

            module_evidence_html += f"""

            <tr>

            <td>{module.get("name","-")}</td>

            <td>{risk.get("level","LOW")}</td>

            <td>{risk.get("score",0)}</td>

            <td>{module.get("author") or "-"}</td>

            <td>{module.get("license") or "-"}</td>

            </tr>

            """

        module_evidence_html += "</table>"

        # Detailed Module Information

        for module in display_modules:

            risk = module.get("risk", {})

            reasons = risk.get("reasons", [])

            if reasons:
                reason_html = "<br>".join(reasons)
            else:
                reason_html = "None"

            deps = module.get("dependencies", [])

            if deps:
                dep_html = ", ".join(deps)
            else:
                dep_html = "-"

            module_evidence_html += f"""

            <h3>{module.get("name","Unknown")}</h3>

            <table>

            <tr><th>Risk</th><td>{risk.get("level","LOW")}</td></tr>

            <tr><th>Risk Score</th><td>{risk.get("score",0)}</td></tr>

            <tr><th>Path</th><td>{module.get("path","-")}</td></tr>

            <tr><th>Description</th><td>{module.get("description") or "-"}</td></tr>

            <tr><th>Author</th><td>{module.get("author") or "-"}</td></tr>

            <tr><th>License</th><td>{module.get("license") or "-"}</td></tr>

            <tr><th>Dependencies</th><td>{dep_html}</td></tr>

            <tr><th>SHA256</th><td>{module.get("sha256","-")}</td></tr>

            <tr><th>Risk Reasons</th><td>{reason_html}</td></tr>

            </table>

            <hr>

            """

        # -------------------------
        # Hidden Module Summary
        # -------------------------

        hidden_summary = hidden_modules.get("summary", {})

        hidden_summary_html = f"""

        <table>

        <tr>
        <th>/proc/modules</th>
        <th>/sys/module</th>
        <th>Ignored Built-ins</th>
        <th>Hidden Modules</th>
        </tr>

        <tr>
        <td>{hidden_summary.get("proc_modules",0)}</td>
        <td>{hidden_summary.get("sys_modules",0)}</td>
        <td>{hidden_summary.get("ignored_builtin",0)}</td>
        <td>{hidden_summary.get("discrepancies",0)}</td>
        </tr>

        </table>

        """

        # -------------------------
        # Hidden Module Evidence Table
        # -------------------------

        hidden_list = hidden_modules.get(
            "hidden_modules",
            []
        )

        if hidden_list:

            hidden_html = """

            <table>

            <tr>

            <th>Hidden Module</th>

            </tr>

            """

            for module in hidden_list:

                hidden_html += f"""

                <tr>

                <td>{module}</td>

                </tr>

                """

            hidden_html += "</table>"

        else:

            hidden_html = """

            <p style="color:green;">

            ✓ No hidden kernel modules detected.

            </p>

            """

        # -------------------------
        # Hidden Process Summary
        # -------------------------

        process_summary = hidden_processes.get("summary", {})

        hidden_process_summary_html = f"""

        <table>

        <tr>
        <th>Running Processes</th>
        <th>Compared Processes</th>
        <th>Discrepancies</th>
        </tr>

        <tr>
        <td>{process_summary.get("running_processes", 0)}</td>
        <td>{process_summary.get("compared_processes", 0)}</td>
        <td>{process_summary.get("discrepancies", 0)}</td>
        </tr>

        </table>

        """

        # -------------------------
        # Hidden Process Table
        # -------------------------

        if hidden_processes.get("findings", []):

            hidden_process_html = """

            <table>

                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Reason</th>
                </tr>

            """

            for process in hidden_processes["findings"]:

                hidden_process_html += f"""

                <tr>

                    <td>{process.get("pid", "-")}</td>

                    <td>{process.get("name", "-")}</td>

                    <td>{process.get("reason", "-")}</td>

                </tr>

                """

            hidden_process_html += "</table>"

        else:

            hidden_process_html = """

            <p style="color:green;">
            ✓ No hidden processes detected.
            </p>

            """

        # -------------------------
        # Kernel Hook Summary
        # -------------------------

        hook_summary = hooks.get("summary", {})

        suspicious_hooks = hook_summary.get("suspicious_hooks", 0)

        hook_summary_html = f"""

        <table>

        <tr>

        <th>DebugFS Mounted</th>

        <th>eBPF Available</th>

        <th>ftrace Enabled</th>

        <th>Kprobes Enabled</th>

        <th>Suspicious Hook Findings</th>

        </tr>

        <tr>

        <td>{hook_summary.get("debugfs_mounted", False)}</td>

        <td>{hook_summary.get("ebpf_available", False)}</td>

        <td>{hook_summary.get("ftrace_enabled", False)}</td>

        <td>{hook_summary.get("kprobes_enabled", False)}</td>

        <td>{suspicious_hooks}</td>

        </tr>

        </table>

        """

        # -------------------------
        # Kernel Hook Findings (HTML Fix 6)
        # -------------------------

        hook_findings = hooks.get("findings", [])

        # Filter to only Warning and Critical findings for the detailed view
        suspicious_findings = [
            f for f in hook_findings
            if f.get("severity") in ("WARNING", "CRITICAL", "SUSPICIOUS")
            or f.get("type") in ("Warning", "Critical")
        ]

        if suspicious_findings:

            hook_table_html = """

            <table>

                <tr>

                    <th>Type</th>

                    <th>Finding</th>

                </tr>

            """

            for finding in suspicious_findings:

                finding_type = finding.get("type", "-")
                message = finding.get("message", "-")
                severity = finding.get("severity", "")

                # Use severity if available, otherwise use type
                display_type = severity if severity else finding_type

                hook_table_html += f"""

                <tr>

                    <td>{display_type}</td>

                    <td>{message}</td>

                </tr>

                """

            hook_table_html += "</table>"

        else:

            hook_table_html = """

            <p style="color:green;">
            ✓ No suspicious kernel hook findings detected.
            </p>

            """

        # -------------------------
        # Kernel Hook Findings Table (HTML Fix 6 - Full table with severity mapping)
        # -------------------------

        hook_full_table_html = ""

        if hook_findings:

            hook_full_table_html = """

            <table>

                <tr>

                    <th>Severity</th>

                    <th>Finding</th>

                </tr>

            """

            for finding in hook_findings:

                severity = finding.get("type", "INFO")

                # Map severity levels properly
                if severity == "Warning":
                    severity = "WARNING"
                elif severity == "Current Tracer":
                    severity = "INFO"
                elif severity == "Available Tracers":
                    severity = "INFO"
                elif severity == "BPF Programs":
                    severity = "INFO"
                elif severity == "Kprobes":
                    severity = "INFO"
                elif severity == "eBPF":
                    severity = "INFO"
                elif severity == "Critical":
                    severity = "CRITICAL"

                hook_full_table_html += f"""

                <tr>

                    <td>{severity}</td>

                    <td>{finding.get("message", finding.get("value", ""))}</td>

                </tr>

                """

            hook_full_table_html += "</table>"

        else:

            hook_full_table_html = "<p>No kernel hook findings available.</p>"

        # -------------------------
        # Kernel Log Summary
        # -------------------------

        log_summary = logs.get("summary", {})

        kernel_log_summary_html = f"""

        <table>

        <tr>

        <th>Warnings</th>

        <th>Errors</th>

        <th>Panics</th>

        <th>Kernel Tainted</th>

        </tr>

        <tr>

        <td>{log_summary.get("warnings",0)}</td>

        <td>{log_summary.get("errors",0)}</td>

        <td>{log_summary.get("panics",0)}</td>

        <td>{log_summary.get("tainted",0)}</td>

        </tr>

        </table>

        """

        # -------------------------
        # Kernel Log Findings
        # -------------------------

        kernel_log_table_html = ""

        findings = logs.get("findings", [])

        if findings:

            kernel_log_table_html = """

            <table>

                <tr>

                    <th>Severity</th>

                    <th>Message</th>

                </tr>

            """

            for finding in findings:

                kernel_log_table_html += f"""

                <tr>

                    <td>{finding.get("type","-")}</td>

                    <td>{finding.get("message","-")}</td>

                </tr>

                """

            kernel_log_table_html += "</table>"

        else:

            kernel_log_table_html = """

            <p>No suspicious kernel log entries detected.</p>

            """

        # -------------------------
        # Network Summary
        # -------------------------

        network_summary = network.get("summary", {})

        network_summary_html = f"""

        <table>

        <tr>

        <th>Total Connections</th>

        <th>Listening Ports</th>

        </tr>

        <tr>

        <td>{network_summary.get("total_connections",0)}</td>

        <td>{network_summary.get("listening_ports",0)}</td>

        </tr>

        </table>

        """

        # -------------------------
        # Network Connection Table
        # -------------------------

        network_table_html = ""

        connections = network.get("connections", [])

        if connections:

            network_table_html = """

            <table>

                <tr>

                    <th>Process</th>

                    <th>PID</th>

                    <th>Local</th>

                    <th>Remote</th>

                    <th>Status</th>

                </tr>

            """

            for conn in connections:

                network_table_html += f"""

                <tr>

                    <td>{conn.get("process") or "-"}</td>

                    <td>{conn.get("pid") or "-"}</td>

                    <td>{conn.get("local","-")}</td>

                    <td>{conn.get("remote","-")}</td>

                    <td>{conn.get("status","-")}</td>

                </tr>

                """

            network_table_html += "</table>"

        else:

            network_table_html = "<p>No active network connections detected.</p>"

        # -------------------------
        # Build Detailed Lists
        # -------------------------

        # Added Modules List (FIXED - Show with risk levels)
        added_modules_html = ""
        added_modules_list = baseline_compare.get("added_modules", [])

        if added_modules_list:
            # Load module data to get risk levels
            modules_data = modules.get("findings", [])
            lookup = {m.get("name"): m for m in modules_data}

            # Filter to only suspicious modules (risk level > LOW)
            suspicious_added = []
            for module_name in added_modules_list:
                info = lookup.get(module_name)
                if info:
                    risk_level = info.get("risk", {}).get("level", "LOW")
                    risk_score = info.get("risk", {}).get("score", 0)
                    reasons = info.get("risk", {}).get("reasons", [])
                    if risk_level != "LOW":
                        suspicious_added.append({
                            "name": module_name,
                            "risk": risk_level,
                            "score": risk_score,
                            "reasons": reasons
                        })

            if suspicious_added:
                added_modules_html = """
                <table>
                    <tr>
                        <th>Module</th>
                        <th>Risk</th>
                        <th>Reason</th>
                    </tr>
                """
                for module in suspicious_added:
                    reason_text = ", ".join(module["reasons"]) if module["reasons"] else "No specific reason"
                    added_modules_html += f"""
                    <tr>
                        <td>{module['name']}</td>
                        <td>{module['risk']}</td>
                        <td>{reason_text}</td>
                    </tr>
                    """
                added_modules_html += "</table>"
            else:
                added_modules_html = "<p>No suspicious module additions detected.</p>"
        else:
            added_modules_html = "<p>No modules added.</p>"

        # Removed Modules List
        removed_modules_html = ""
        removed_modules_list = baseline_compare.get("removed_modules", [])
        if removed_modules_list:
            removed_modules_html = "<ul>"
            for module in removed_modules_list:
                removed_modules_html += f"<li>{module}</li>"
            removed_modules_html += "</ul>"
        else:
            removed_modules_html = "<p>No modules removed.</p>"

        # Added Ports List
        added_ports_html = ""
        added_ports_list = baseline_compare.get("added_ports", [])
        if added_ports_list:
            added_ports_html = "<ul>"
            for port in added_ports_list:
                if isinstance(port, dict):
                    added_ports_html += f"<li>{port.get('local', 'Unknown')} ({port.get('process', 'Unknown')})</li>"
                else:
                    added_ports_html += f"<li>{port}</li>"
            added_ports_html += "</ul>"
        else:
            added_ports_html = "<p>No new listening ports detected.</p>"

        # Removed Ports List
        removed_ports_html = ""
        removed_ports_list = baseline_compare.get("removed_ports", [])
        if removed_ports_list:
            removed_ports_html = "<ul>"
            for port in removed_ports_list:
                if isinstance(port, dict):
                    removed_ports_html += f"<li>{port.get('local', 'Unknown')} ({port.get('process', 'Unknown')})</li>"
                else:
                    removed_ports_html += f"<li>{port}</li>"
            removed_ports_html += "</ul>"
        else:
            removed_ports_html = "<p>No ports removed.</p>"

        # Hidden Modules Detailed List
        hidden_modules_detailed_html = ""
        if hidden_list:
            hidden_modules_detailed_html = "<ul>"
            for module in hidden_list:
                hidden_modules_detailed_html += f"<li>{module}</li>"
            hidden_modules_detailed_html += "</ul>"
        else:
            hidden_modules_detailed_html = "<p>No hidden modules detected.</p>"

        # Hidden Processes Detailed List
        hidden_processes_detailed_html = ""
        if hidden_processes.get("findings", []):
            hidden_processes_detailed_html = "<ul>"
            for process in hidden_processes["findings"]:
                pid = process.get("pid", "-")
                name = process.get("name", "-")
                reason = process.get("reason", "-")
                hidden_processes_detailed_html += f"<li>PID {pid}: {name} ({reason})</li>"
            hidden_processes_detailed_html += "</ul>"
        else:
            hidden_processes_detailed_html = "<p>No hidden processes detected.</p>"

        # IOC Matches Detailed List
        ioc_detailed_html = ""
        if ioc.get("findings", []):
            ioc_detailed_html = "<ul>"
            for finding in ioc.get("findings", []):
                indicator = finding.get("indicator", "-")
                severity = finding.get("severity", "-")
                description = finding.get("description", "-")
                ioc_detailed_html += f"<li><strong>{indicator}</strong> ({severity}) - {description}</li>"
            ioc_detailed_html += "</ul>"
        else:
            ioc_detailed_html = "<p>No Indicators of Compromise detected.</p>"

        # Kernel Hooks Detailed List
        hooks_detailed_html = ""
        if suspicious_findings:
            hooks_detailed_html = "<ul>"
            for finding in suspicious_findings:
                finding_type = finding.get("type", "-")
                message = finding.get("message", "-")
                severity = finding.get("severity", "")
                display_type = severity if severity else finding_type
                hooks_detailed_html += f"<li><strong>{display_type}</strong>: {message}</li>"
            hooks_detailed_html += "</ul>"
        else:
            hooks_detailed_html = "<p>No suspicious kernel hook findings.</p>"

        # -------------------------
        # Load HTML Template
        # -------------------------

        template = os.path.join(
            "reports",
            "templates",
            "report_template.html"
        )

        with open(template, "r") as f:

            html = f.read()

        # -------------------------
        # Threat Badge
        # -------------------------

        level = threat.get(
            "threat_level",
            "LOW"
        )

        level_class = level.lower()

        # Format AI analysis with line breaks
        formatted_ai = ai_analysis.replace("\n", "<br>")

        # -------------------------
        # Placeholder Values
        # -------------------------

        replacements = {

            "{{CASE_ID}}": self.case.get_case_id(),

            "{{DATE}}": datetime.now().strftime(
                "%d %B %Y %H:%M"
            ),

            "{{THREAT_SCORE}}": str(
                threat.get(
                    "threat_score",
                    0
                )
            ),

            "{{THREAT_LEVEL}}": level,

            "{{LEVEL_CLASS}}": level_class,

            "{{HOSTNAME}}": kernel.get(
                "hostname",
                "-"
            ),

            "{{SYSTEM}}": kernel.get(
                "system",
                "-"
            ),

            "{{KERNEL}}": kernel.get(
                "kernel_release",
                "-"
            ),

            "{{ARCH}}": kernel.get(
                "architecture",
                "-"
            ),

            "{{UPTIME}}": str(
                kernel.get(
                    "uptime_seconds",
                    0
                )
            ),

            "{{TOTAL_MODULES}}": str(
                modules.get(
                    "summary",
                    {}
                ).get(
                    "modules_scanned",
                    0
                )
            ),

            "{{HIGH_MODULES}}": str(
                modules.get(
                    "summary",
                    {}
                ).get(
                    "high_risk",
                    0
                )
            ),

            "{{MEDIUM_MODULES}}": str(
                modules.get(
                    "summary",
                    {}
                ).get(
                    "medium_risk",
                    0
                )
            ),

            "{{LOW_MODULES}}": str(
                modules.get(
                    "summary",
                    {}
                ).get(
                    "low_risk",
                    0
                )
            ),

            "{{HIDDEN_MODULES}}": str(
                hidden_modules.get(
                    "summary",
                    {}
                ).get(
                    "discrepancies",
                    0
                )
            ),

            "{{HIDDEN_PROCESSES}}": str(
                hidden_processes.get(
                    "summary",
                    {}
                ).get(
                    "discrepancies",
                    0
                )
            ),

            "{{LISTENING_PORTS}}": str(
                network.get(
                    "summary",
                    {}
                ).get(
                    "listening_ports",
                    0
                )
            ),

            "{{KERNEL_ERRORS}}": str(
                logs.get(
                    "summary",
                    {}
                ).get(
                    "errors",
                    0
                )
            ),

            "{{KERNEL_PANICS}}": str(
                logs.get(
                    "summary",
                    {}
                ).get(
                    "panics",
                    0
                )
            ),

            "{{KERNEL_WARNINGS}}": str(
                logs.get(
                    "summary",
                    {}
                ).get(
                    "warnings",
                    0
                )
            ),

            "{{KERNEL_HOOKS}}": str(
                suspicious_hooks
            ),

            "{{PERSISTENCE}}": str(
                persistence.get(
                    "summary",
                    {}
                ).get(
                    "suspicious_entries",
                    0
                )
            ),

            "{{ADDED_MODULES_COUNT}}": str(
                len(
                    baseline_compare.get(
                        "added_modules",
                        []
                    )
                )
            ),

            "{{REMOVED_MODULES_COUNT}}": str(
                len(
                    baseline_compare.get(
                        "removed_modules",
                        []
                    )
                )
            ),

            "{{ADDED_PORTS_COUNT}}": str(
                len(
                    baseline_compare.get(
                        "added_ports",
                        []
                    )
                )
            ),

            "{{REMOVED_PORTS_COUNT}}": str(
                len(
                    baseline_compare.get(
                        "removed_ports",
                        []
                    )
                )
            ),

            "{{CORRELATION_SCORE}}": str(
                correlation.get(
                    "total_score",
                    0
                )
            ),

            "{{MITRE_COUNT}}": str(
                mitre.get(
                    "summary",
                    {}
                ).get(
                    "techniques_detected",
                    0
                )
            ),

            "{{IOC_COUNT}}": str(
                ioc.get(
                    "summary",
                    {}
                ).get(
                    "ioc_matches",
                    0
                )
            ),

            # Module summary and table
            "{{MODULE_SUMMARY}}": module_summary_html,
            "{{MODULE_TABLE}}": module_table_html,

            # Module evidence (detailed)
            "{{MODULE_EVIDENCE}}": module_evidence_html,

            # Hidden module analysis
            "{{HIDDEN_MODULE_SUMMARY}}": hidden_summary_html,
            "{{HIDDEN_MODULE_TABLE}}": hidden_html,

            # Hidden process analysis
            "{{HIDDEN_PROCESS_SUMMARY}}": hidden_process_summary_html,
            "{{HIDDEN_PROCESS_TABLE}}": hidden_process_html,

            # Kernel hook analysis
            "{{HOOK_SUMMARY}}": hook_summary_html,
            "{{HOOK_TABLE}}": hook_table_html,
            "{{HOOK_FULL_TABLE}}": hook_full_table_html,

            # Kernel log analysis
            "{{KERNEL_LOG_SUMMARY}}": kernel_log_summary_html,
            "{{KERNEL_LOG_TABLE}}": kernel_log_table_html,

            # Network analysis
            "{{NETWORK_SUMMARY}}": network_summary_html,
            "{{NETWORK_TABLE}}": network_table_html,

            # Detailed lists
            "{{ADDED_MODULES_LIST}}": added_modules_html,
            "{{REMOVED_MODULES_LIST}}": removed_modules_html,
            "{{ADDED_PORTS_LIST}}": added_ports_html,
            "{{REMOVED_PORTS_LIST}}": removed_ports_html,
            "{{HIDDEN_MODULES_DETAILED}}": hidden_modules_detailed_html,
            "{{HIDDEN_PROCESSES_DETAILED}}": hidden_processes_detailed_html,
            "{{IOC_DETAILED}}": ioc_detailed_html,
            "{{KERNEL_HOOKS_DETAILED}}": hooks_detailed_html,
            
            "{{AI_ANALYSIS}}": formatted_ai,
        }

        # -------------------------
        # HTML Fix 1 - Baseline Replacements
        # -------------------------

        if baseline_compare:
            html = html.replace(
                "{{ADDED_MODULES}}",
                str(len(baseline_compare.get("added_modules", [])))
            )
            html = html.replace(
                "{{REMOVED_MODULES}}",
                str(len(baseline_compare.get("removed_modules", [])))
            )
            html = html.replace(
                "{{ADDED_PORTS}}",
                str(len(baseline_compare.get("added_ports", [])))
            )
            html = html.replace(
                "{{REMOVED_PORTS}}",
                str(len(baseline_compare.get("removed_ports", [])))
            )

        # -------------------------
        # HTML Fix 8 - Threat Findings directly from Threat Assessment
        # -------------------------

        threat_findings_html = ""
        for reason in threat.get("reasons", []):
            threat_findings_html += f"<li>{reason}</li>"

        html = html.replace(
            "{{THREAT_FINDINGS}}",
            threat_findings_html
        )

        # -------------------------
        # HTML Fix 9 - Recommendations directly from Threat Assessment
        # -------------------------

        recommendation_html = ""
        for recommendation in threat.get("recommendations", []):
            recommendation_html += f"<li>{recommendation}</li>"

        html = html.replace(
            "{{RECOMMENDATIONS}}",
            recommendation_html
        )

        # -------------------------
        # Executive Summary
        # -------------------------

        summary_items = [
            f"{modules.get('summary', {}).get('modules_scanned', 0)} kernel modules analyzed.",
            f"{hidden_modules.get('summary', {}).get('discrepancies', 0)} hidden modules detected.",
            f"{hidden_processes.get('summary', {}).get('discrepancies', 0)} hidden processes detected.",
            f"{suspicious_hooks} suspicious kernel hook findings.",
            f"Evidence integrity: {integrity_report.get('status', 'UNKNOWN')}.",
            f"Threat Score: {threat.get('threat_score',0)}/100 ({threat.get('threat_level','LOW')})."
        ]

        # Add baseline comparison items
        added_modules_count = len(baseline_compare.get('added_modules', []))
        added_ports_count = len(baseline_compare.get('added_ports', []))

        if added_modules_count > 0:
            summary_items.append(f"{added_modules_count} module(s) added since baseline.")

        if added_ports_count > 0:
            summary_items.append(f"{added_ports_count} listening port(s) added.")

        executive_summary = "<ul>"
        for item in summary_items:
            executive_summary += f"<li>{item}</li>"
        executive_summary += "</ul>"

        html = html.replace("{{EXECUTIVE_SUMMARY}}", executive_summary)

        # -------------------------
        # Investigation Actions
        # -------------------------

        actions = """
        <ol>
        <li>Review suspicious kernel hook findings.</li>
        <li>Validate loaded kernel modules.</li>
        <li>Inspect kernel logs.</li>
        <li>Compare with trusted baseline.</li>
        <li>Preserve all evidence for forensic investigation.</li>
        </ol>
        """

        html = html.replace("{{INVESTIGATION_ACTIONS}}", actions)

        # -------------------------
        # HTML Fix 10 - Evidence Statistics (Dynamic)
        # -------------------------

        verified_count = len(integrity_report.get("verified", []))
        tampered_count = len(integrity_report.get("tampered", []))
        timeline_events = len(timeline.get("events", []))
        mitre_count = mitre.get("summary", {}).get("techniques_detected", 0)
        ioc_count = ioc.get("summary", {}).get("ioc_matches", 0)
        correlation_count = len(correlation.get("findings", []))

        html = html.replace("{{VERIFIED_FILES}}", str(verified_count))
        html = html.replace("{{TAMPERED_FILES}}", str(tampered_count))
        html = html.replace("{{TIMELINE_EVENTS}}", str(timeline_events))
        html = html.replace("{{MITRE_COUNT}}", str(mitre_count))
        html = html.replace("{{IOC_COUNT}}", str(ioc_count))
        html = html.replace("{{CORRELATION_COUNT}}", str(correlation_count))

        # Also update the evidence_stats display
        evidence_stats = f"""
        <table>
        <tr><th>Statistic</th><th>Value</th></tr>
        <tr><td>Evidence Files Verified</td><td>{verified_count}</td></tr>
        <tr><td>Evidence Files Tampered</td><td>{tampered_count}</td></tr>
        <tr><td>Timeline Events</td><td>{timeline_events}</td></tr>
        <tr><td>MITRE Techniques</td><td>{mitre_count}</td></tr>
        <tr><td>IOC Matches</td><td>{ioc_count}</td></tr>
        <tr><td>Correlation Rules</td><td>{correlation_count}</td></tr>
        </table>
        """

        html = html.replace("{{EVIDENCE_STATS}}", evidence_stats)

        # -------------------------
        # Evidence Directory
        # -------------------------

        output_path = os.path.join(
            self.output_dir,
            f"AKRDFAS_{self.case.get_case_id()}.html"
        )

        directory = f"""
        <table>
        <tr><th>Location</th><th>Path</th></tr>
        <tr><td>Case Directory</td><td>{self.case_dir}</td></tr>
        <tr><td>Evidence Directory</td><td>{self.evidence_dir}</td></tr>
        <tr><td>Generated Report</td><td>{output_path}</td></tr>
        </table>
        """

        html = html.replace("{{EVIDENCE_DIRECTORY}}", directory)

        # -------------------------
        # Case Conclusion
        # -------------------------

        conclusion = f"""
        <p>
        Investigation completed successfully.<br><br>

        Hidden Modules Detected: {hidden_modules.get("summary",{}).get("discrepancies",0)}<br>
        Hidden Processes Detected: {hidden_processes.get("summary",{}).get("discrepancies",0)}<br>
        Evidence Integrity: {integrity_report.get("status","UNKNOWN")}<br>
        Overall Threat Level: {threat.get("threat_level","LOW")}<br><br>

        Further manual investigation is recommended for suspicious findings before concluding the system is fully trusted.
        </p>
        """

        html = html.replace("{{CASE_CONCLUSION}}", conclusion)

        # -------------------------
        # Threat Score Breakdown (HTML Fix 4)
        # -------------------------

        # Calculate hook contribution properly
        hook_points = min(suspicious_hooks * 10, 20)

        threat_breakdown = f"""
        <table>
        <tr><th>Detection</th><th>Findings</th><th>Contribution</th></tr>

        <tr><td>Hidden Processes</td><td>{hidden_processes.get("summary",{}).get("discrepancies",0)}</td><td>Dynamic</td></tr>

        <tr><td>Hidden Modules</td><td>{hidden_modules.get("summary",{}).get("discrepancies",0)}</td><td>Dynamic</td></tr>

        <tr><td>Kernel Hooks</td><td>{suspicious_hooks}</td><td>+{hook_points}</td></tr>

        <tr><td>Kernel Errors</td><td>{logs.get("summary",{}).get("errors",0)}</td><td>Dynamic</td></tr>

        <tr><td>Persistence</td><td>{persistence.get("summary",{}).get("suspicious_entries",0)}</td><td>Dynamic</td></tr>

        <tr><td>Correlation Score</td><td>{correlation.get("total_score",0)}</td><td>+{correlation.get("total_score",0)}</td></tr>

        <tr><td>IOC Matches</td><td>{ioc.get("summary",{}).get("ioc_matches",0)}</td><td>Dynamic</td></tr>

        </table>
        """

        html = html.replace("{{THREAT_BREAKDOWN}}", threat_breakdown)

        # -------------------------
        # HTML Fix 7 - MITRE ATT&CK Table (use actual reason)
        # -------------------------

        mitre_html = ""

        if mitre.get("techniques", []):

            mitre_html += """

            <table>

                <tr>

                    <th>Technique</th>

                    <th>Name</th>

                    <th>Severity</th>

                    <th>Evidence</th>

                </tr>

            """

            for technique in mitre.get("techniques", []):

                mitre_html += f"""

                <tr>

                    <td>{technique.get('id', '-')}</td>

                    <td>{technique.get('name', '-')}</td>

                    <td>{technique.get('severity', '-')}</td>

                    <td>{technique.get('reason', '-')}</td>

                </tr>

                """

            mitre_html += "</table>"

        else:

            mitre_html = "<p>No MITRE ATT&CK techniques identified.</p>"

        html = html.replace("{{MITRE_TABLE}}", mitre_html)

        # -------------------------
        # Correlation Table
        # -------------------------

        correlation_html = ""

        if correlation.get("findings", []):

            correlation_html += """

            <table>

                <tr>

                    <th>Rule</th>

                    <th>Severity</th>

                    <th>Description</th>

                </tr>

            """

            for finding in correlation.get("findings", []):

                correlation_html += f"""

                <tr>

                    <td>{finding.get('rule', '-')}</td>

                    <td>{finding.get('severity', '-')}</td>

                    <td>{finding.get('description', '-')}</td>

                </tr>

                """

            correlation_html += "</table>"

        else:

            correlation_html = "<p>No correlation rules matched.</p>"

        html = html.replace("{{CORRELATION_TABLE}}", correlation_html)


        # -------------------------
        # IOC Matches Table
        # -------------------------

        ioc_html = ""

        if ioc.get("findings", []):

            ioc_html += """

            <table>

                <tr>

                    <th>IOC</th>

                    <th>Severity</th>

                    <th>Description</th>

                </tr>

            """

            for finding in ioc.get("findings", []):

                ioc_html += f"""

                <tr>

                    <td>{finding.get('indicator', '-')}</td>

                    <td>{finding.get('severity', '-')}</td>

                    <td>{finding.get('description', '-')}</td>

                </tr>

                """

            ioc_html += "</table>"

        else:

            ioc_html = "<p>No Indicators of Compromise detected.</p>"

        html = html.replace("{{IOC_TABLE}}", ioc_html)

        # -------------------------
        # Evidence Integrity Table
        # -------------------------

        integrity_html = """

        <table>

            <tr>

                <th>Evidence File</th>

                <th>Status</th>

            </tr>

        """

        for filename in integrity_report.get("verified", []):

            integrity_html += f"""

            <tr>

                <td>{filename}</td>

                <td>VERIFIED</td>

            </tr>

            """

        for filename in integrity_report.get("tampered", []):

            integrity_html += f"""

            <tr>

                <td>{filename}</td>

                <td>TAMPERED</td>

            </tr>

            """

        integrity_html += "</table>"

        if not integrity_report.get("verified") and not integrity_report.get("tampered"):

            integrity_html = "<p>No evidence integrity information available.</p>"

        html = html.replace("{{INTEGRITY_TABLE}}", integrity_html)

        # -------------------------
        # Evidence Inventory
        # -------------------------

        evidence_html = """

        <table>

            <tr>

                <th>Evidence File</th>

                <th>Description</th>

            </tr>

        """

        descriptions = {
            "kernel_information.json": "Kernel and operating system information",
            "kernel_baseline.json": "Trusted baseline information",
            "kernel_modules.json": "Loaded kernel modules",
            "hidden_modules.json": "Hidden kernel module analysis",
            "hidden_processes.json": "Hidden process detection",
            "kernel_integrity.json": "Kernel integrity verification",
            "network_connections.json": "Active network connections",
            "persistence.json": "Persistence mechanism analysis",
            "kernel_hooks.json": "Kernel hook inspection",
            "kernel_logs.json": "Kernel log analysis",
            "baseline_comparison.json": "Comparison against trusted baseline",
            "correlation_findings.json": "Threat correlation results",
            "mitre_mapping.json": "MITRE ATT&CK mappings",
            "ioc_matches.json": "Indicators of Compromise results",
            "integrity_verification.json": "Evidence integrity verification",
            "timeline.json": "Investigation timeline",
            "threat_assessment.json": "Threat assessment results",
            "ai_explanation.json": "AI investigation analysis"
        }

        for filename, description in descriptions.items():

            if os.path.exists(os.path.join(self.evidence_dir, filename)):

                evidence_html += f"""

                <tr>

                    <td>{filename}</td>

                    <td>{description}</td>

                </tr>

                """

        evidence_html += "</table>"

        html = html.replace("{{EVIDENCE_TABLE}}", evidence_html)

        # -------------------------
        # Investigation Timeline (HTML Fix 5 - Improved)
        # -------------------------

        timeline_table = ""

        if timeline and timeline.get("events"):

            timeline_table += """
            <table class="table">

                <tr>
                    <th>Time</th>
                    <th>Event</th>
                </tr>
            """

            for event in timeline["events"]:

                timeline_table += f"""
                <tr>
                    <td>{event.get('time', '-')}</td>
                    <td>{event.get('event', '-')}</td>
                </tr>
                """

            timeline_table += "</table>"

        else:

            timeline_table = "<p>No timeline information available.</p>"

        html = html.replace(
            "{{TIMELINE_TABLE}}",
            timeline_table
        )

        # Also keep the timeline rows placeholder for backward compatibility
        timeline_rows = ""

        if timeline and timeline.get("events"):

            for event in timeline.get("events", []):
                timeline_rows += f"""
                <tr>
                    <td>{event.get('time', '-')}</td>
                    <td>{event.get('event', '-')}</td>
                </tr>
                """

        else:

            timeline_rows = """
            <tr>
                <td colspan="2">No timeline information available.</td>
            </tr>
            """

        html = html.replace("{{TIMELINE_ROWS}}", timeline_rows)

        # -------------------------
        # Insert CSS into Template
        # -------------------------

        html = html.replace("{{CSS_STYLES}}", css)

        # -------------------------
        # Replace All Remaining Placeholders
        # -------------------------

        for key, value in replacements.items():
            html = html.replace(key, str(value))

        # -------------------------
        # Save HTML Report
        # -------------------------

        output = os.path.join(
            self.output_dir,
            f"AKRDFAS_{self.case.get_case_id()}.html"
        )

        with open(output, "w", encoding="utf-8") as f:
            f.write(html)

        print("[✓] HTML Report Generated")