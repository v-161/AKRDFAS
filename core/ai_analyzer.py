import os
import json

from dotenv import load_dotenv
from google import genai


class AIAnalyzer:

    def __init__(self, case_manager):

        load_dotenv()

        self.case = case_manager

        self.evidence_dir = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise Exception(
                "GEMINI_API_KEY not found in .env"
            )

        self.client = genai.Client(
            api_key=api_key
        )

    # -----------------------------------------

    def load(self, filename):

        path = os.path.join(
            self.evidence_dir,
            filename
        )

        if not os.path.exists(path):
            return {}

        with open(path, "r") as f:
            return json.load(f)

    # -----------------------------------------

    def build_prompt(self):

        threat = self.load("threat_assessment.json")
        correlation = self.load("correlation_findings.json")
        mitre = self.load("mitre_mapping.json")
        ioc = self.load("ioc_matches.json")
        hidden_modules = self.load("hidden_modules.json")
        hidden_processes = self.load("hidden_processes.json")
        hooks = self.load("kernel_hooks.json")
        logs = self.load("kernel_logs.json")
        integrity = self.load("kernel_integrity.json")

        prompt = f"""
You are a Senior Linux Kernel Digital Forensics Investigator.

You are analysing the results produced by AKRDFAS
(Advanced Kernel Rootkit Detection and Forensic Analysis System).

The following JSON objects are investigation evidence.

Threat Assessment:
{json.dumps(threat, indent=2)}

Correlation Findings:
{json.dumps(correlation, indent=2)}

MITRE Mapping:
{json.dumps(mitre, indent=2)}

IOC Matches:
{json.dumps(ioc, indent=2)}

Kernel Hooks:
{json.dumps(hooks, indent=2)}

Hidden Modules:
{json.dumps(hidden_modules, indent=2)}

Hidden Processes:
{json.dumps(hidden_processes, indent=2)}

Kernel Integrity:
{json.dumps(integrity, indent=2)}

Kernel Logs:
{json.dumps(logs, indent=2)}

Provide:

1. Executive Summary (2-3 sentences maximum)

2. Explain WHY this threat score was assigned (2-3 sentences)

3. Explain each suspicious finding (brief bullet points)

4. Explain possible attacker behaviour (2-3 sentences)

5. Explain business/security impact (2-3 sentences)

6. Recommend investigation steps (brief list)

7. Recommend remediation steps (brief list)

8. Mention if immediate response is required (1 sentence)

IMPORTANT INSTRUCTIONS:

1. You are an AI forensic analyst assisting AKRDFAS.

2. Do NOT calculate or change the threat score.

3. Do NOT modify the threat level.

4. Explain the evidence collected by AKRDFAS.

5. Write professionally and concisely.

6. Generate plain investigation text. Do NOT use markdown formatting.

7. Do NOT use: #, ##, ###, ---, **, __, `, or any markdown symbols.

8. Use only plain English headings with colons and simple paragraphs.

9. Keep each section brief and to the point.

10. Do NOT repeat raw JSON.

Example format:

Executive Summary: Brief 2-3 line summary here.

Threat Score Assignment: Brief explanation here.

Suspicious Findings: Brief bullet points here.

Attacker Behaviour: Brief explanation here.

Impact: Brief explanation here.

Investigation Steps: Brief list here.

Remediation Steps: Brief list here.

Immediate Response: Yes/No with brief reason.
"""

        return prompt

    # -----------------------------------------

    def run(self):

        prompt = self.build_prompt()

        response = self.client.models.generate_content(
            model="models/gemini-3.5-flash",
            contents=prompt
        )

        output = {

            "model": "models/gemini-3.5-flash",

            "analysis": response.text

        }

        output_path = os.path.join(
            self.evidence_dir,
            "ai_explanation.json"
        )

        with open(output_path, "w") as f:

            json.dump(
                output,
                f,
                indent=4
            )

        print("[✓] AI Investigation Analysis Generated")