import psutil
import socket

from core.detector import BaseDetector


class NetworkDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

    def run(self):

        self.logger.info(
            "Starting Network Detector"
        )

        connections = []

        listening = 0

        for conn in psutil.net_connections(kind="inet"):

            try:

                local = ""

                remote = ""

                if conn.laddr:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"

                if conn.raddr:
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}"

                if conn.status == "LISTEN":
                    listening += 1

                process = None

                if conn.pid:

                    try:
                        process = psutil.Process(conn.pid).name()
                    except Exception:
                        process = "Unknown"

                username = None

                if conn.pid:

                    try:

                        username = psutil.Process(conn.pid).username()

                    except:

                        username = "Unknown"

                is_loopback = local.startswith("127.") if local else False

                is_privileged = False

                if conn.laddr:

                    if conn.laddr.port < 1024:

                        is_privileged = True

                connections.append({

                    "pid": conn.pid,

                    "process": process,

                    "username": username,

                    "protocol": "TCP" if conn.type == 1 else "UDP",

                    "family": str(conn.family),

                    "local": local,

                    "remote": remote,

                    "status": conn.status,

                    "loopback": is_loopback,

                    "privileged_port": is_privileged

                })

            except Exception:
                pass

        tcp = sum(

            1

            for c in connections

            if c["protocol"] == "TCP"

        )

        udp = sum(

            1

            for c in connections

            if c["protocol"] == "UDP"

        )

        loopback = sum(

            1

            for c in connections

            if c["loopback"]

        )

        privileged = sum(

            1

            for c in connections

            if c["privileged_port"]

        )

        self.evidence.add(

            "network_connections",

            {

                "summary": {

                    "total_connections": len(connections),

                    "listening_ports": listening,

                    "tcp_connections": tcp,

                    "udp_connections": udp,

                    "loopback_connections": loopback,

                    "privileged_ports": privileged

                },

                "connections": connections

            }

        )

        print(
            f"[✓] Network Analysis ({len(connections)} connections)"
        )

        self.logger.info(
            "Network Detector Finished"
        )
