from typing import Dict, Any

class RiskAnalyzer:
    # Industry-standard insecure protocols mapping
    RISKY_SERVICES = {
        21: {"service": "FTP", "risk": "HIGH", "rec": "FTP transmits credentials in plaintext. Upgrade to SFTP or FTPS."},
        23: {"service": "Telnet", "risk": "CRITICAL", "rec": "Telnet transmits all traffic unencrypted. Immediately replace with SSH (Port 22)."},
        445: {"service": "SMB", "risk": "HIGH", "rec": "Exposed SMB is highly susceptible to lateral movement exploits (e.g., EternalBlue). Restrict access via firewall."},
        3389: {"service": "RDP", "risk": "MEDIUM", "rec": "Exposed RDP is targeted for brute-force attacks. Implement MFA, change default port, or use a VPN."}
    }

    @classmethod
    def analyze_port(cls, port: int) -> Dict[str, Any]:
        """Evaluates whether an open port poses a critical compliance or security risk."""
        if port in cls.RISKY_SERVICES:
            return {
                "is_risky": True,
                "risk_level": cls.RISKY_SERVICES[port]["risk"],
                "recommendation": cls.RISKY_SERVICES[port]["rec"]
            }
        return {"is_risky": False, "risk_level": "LOW", "recommendation": "N/A"}