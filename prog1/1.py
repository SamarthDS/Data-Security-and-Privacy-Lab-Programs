"""
Email & Document Virus Simulator (Safe, Educational)

This is a fully safe, non-malicious Python simulator for educational use.
It *models* common malware/phishing behaviors at an abstract level so you
can study attack chains, detection techniques, and mitigation strategies
without touching real systems or executing harmful payloads.

Key features:
- Simulated environment of users, endpoints (nodes), mailboxes, and documents
- Attack vectors: phishing email with attachments, malicious document macros,
  and link-based lure (drive-by simulation)
- Payloads are *simulated effects* (state changes and logs) and do NOT perform
  any real file/network operations
- Detection modules: signature-based, heuristic scoring, and a simple
  anomaly detector
- Reporting and a reproducible CLI-driven simulation

Usage:
    python email_document_virus_simulator.py --help

Safety notice:
- This script intentionally avoids network I/O, file system modifications,
  code execution, self-replication, or any action that could be harmful.
- Use it for learning, classroom demos, or red-team/blue-team tabletop drills.

Author: Educational template
License: MIT (for educational use)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import random
import time
import argparse
import csv
import json
import statistics

# ----------------------------- Simulation Models -----------------------------

@dataclass
class Document:
    name: str
    content: str
    has_macro: bool = False
    macro_behavior: Optional[str] = None  # descriptive only

@dataclass
class Email:
    sender: str
    recipient: str
    subject: str
    body: str
    attachment: Optional[Document] = None
    link: Optional[str] = None  # simulated URL

@dataclass
class Node:
    id: str
    user: str
    compromised: bool = False
    compromise_vector: Optional[str] = None
    files: List[Document] = field(default_factory=list)
    mailbox: List[Email] = field(default_factory=list)
    detection_alerts: List[Dict] = field(default_factory=list)

    def receive_email(self, email: Email):
        self.mailbox.append(email)

    def open_email(self, index: int) -> Optional[Email]:
        try:
            return self.mailbox[index]
        except IndexError:
            return None

# ----------------------------- Attack Simulation -----------------------------

class Attacker:
    """Abstract attacker that can craft phishing emails and malicious docs."""
    def __init__(self, name: str = "Attacker"):
        self.name = name

    def craft_phishing_email(self, target_user: str, lure: str = "invoice") -> Email:
        # Simulate a realistic-looking phishing email (descriptive only)
        subj = f"{lure.title()} - Action Required"
        body = (
            f"Hi {target_user},\n\nPlease see the attached {lure}. If you have issues, reply to this email.\n\nThanks\n{self.name}"
        )
        # Create a "malicious" document that only contains descriptive macro behavior
        doc = Document(
            name=f"{lure}_{random.randint(100,999)}.docm",
            content=f"Simulated {lure} content for {target_user}",
            has_macro=True,
            macro_behavior="exfiltrate_simulated_credentials"
        )
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, attachment=doc)

    def craft_malicious_link_email(self, target_user: str, domain: str = "bad.example") -> Email:
        subj = "Security Alert - Verify Your Account"
        body = f"Dear {target_user}, please verify here: http://{domain}/verify"
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, link=f"http://{domain}/verify")

# ----------------------------- Detection Modules -----------------------------

class SignatureDetector:
    """Simple signature detector that flags emails/documents containing
    known bad patterns (simulated signatures)."""
    KNOWN_SIGNATURES = [
        "exfiltrate_simulated_credentials",
        "evil_macro",
        "drop_ransom_note",
        "keylogger_stub",
    ]

    def scan_document(self, doc: Document) -> Optional[str]:
        # purely string-based descriptive signatures
        if doc.macro_behavior and doc.macro_behavior in self.KNOWN_SIGNATURES:
            return f"signature:{doc.macro_behavior}"
        for sig in self.KNOWN_SIGNATURES:
            if sig in doc.content:
                return f"signature_in_content:{sig}"
        return None

    def scan_email(self, email: Email) -> Optional[str]:
        if email.attachment:
            return self.scan_document(email.attachment)
        if email.link and "bad.example" in (email.link or ""):
            return "signature:malicious-link-bad-example"
        return None

class HeuristicDetector:
    """Rule-based heuristics returning a risk score and reasons.
    Scores are illustrative; tune for your scenario."""
    SHORT_URL_DOMAINS = {"bit.ly", "t.co", "tinyurl.com"}

    def score_email(self, email: Email) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        subj = (email.subject or "").lower()
        body = (email.body or "").lower()

        if any(word in subj for word in ["action required", "verify", "urgent", "security alert"]):
            score += 0.3
            reasons.append("suspicious-subject")
        if email.link:
            score += 0.3
            reasons.append("contains-link")
            if any(s in email.link for s in self.SHORT_URL_DOMAINS):
                score += 0.2
                reasons.append("shortener-link")
            if "bad.example" in email.link:
                score += 0.5
                reasons.append("known-bad-domain")
        if email.attachment:
            score += 0.25
            reasons.append("attachment-present")
            if email.attachment.has_macro:
                score += 0.4
                reasons.append("macro-attachment")
        # clamp
        score = min(score, 1.0)
        return score, reasons

class AnomalyDetector:
    """Very simple anomaly detector using behavioral baselines.
    This is purely illustrative and uses message rates as a proxy."""
    def __init__(self):
        self.baseline_message_counts = {}  # user -> avg

    def update_baseline(self, user: str, count: int):
        self.baseline_message_counts[user] = int(round(count))

    def is_anomalous(self, user: str, current_count: int) -> Tuple[bool, float]:
        baseline = self.baseline_message_counts.get(user, max(1, current_count))
        # flag if current_count is > 3x baseline
        ratio = current_count / (baseline if baseline > 0 else 1)
        return ratio > 3.0, ratio

# ----------------------------- Simulator Engine -----------------------------

class Simulator:
    def __init__(self, num_nodes: int = 10, seed: Optional[int] = None):
        self.nodes: Dict[str, Node] = {}
        self.attacker = Attacker()
        self.sig = SignatureDetector()
        self.heur = HeuristicDetector()
        self.ano = AnomalyDetector()
        self.time = 0
        if seed is not None:
            random.seed(seed)

        for i in range(num_nodes):
            user = f"user{i+1}@example.com"
            node = Node(id=f"node{i+1}", user=user)
            # create a few benign documents
            node.files.append(Document(name="welcome.txt", content="Welcome user"))
            self.nodes[node.id] = node

    def send_email(self, target_node_id: str, email: Email):
        node = self.nodes[target_node_id]
        node.receive_email(email)

    def simulate_phishing_campaign(self, targets: List[str], lure: str = "invoice", click_rate: float = 0.2):
        """Attacker sends phishing emails to target nodes and some fraction opens/executes."""
        events = []
        for t in targets:
            email = self.attacker.craft_phishing_email(self.nodes[t].user, lure=lure)
            self.send_email(t, email)
            events.append((t, "sent_phishing", email.subject))

            # Detection phase (email gateway checks)
            sig = self.sig.scan_email(email)
            score, reasons = self.heur.score_email(email)

            # If signature found: immediate alert (no remote action simulated)
            if sig:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
                events.append((t, "detected_by_signature", sig))
            elif score >= 0.7:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
                events.append((t, "detected_by_heuristic", reasons))

            # User behavior: may open and execute attachment (simulated probability)
            if random.random() < click_rate:
                # "Execute" the attachment in a sandboxed way (no real execution)
                doc = email.attachment
                exec_result = self._simulate_attachment_execution(t, doc)
                events.append((t, "attachment_executed", exec_result))
        return events

    def simulate_link_campaign(self, targets: List[str], click_rate: float = 0.15):
        events = []
        for t in targets:
            email = self.attacker.craft_malicious_link_email(self.nodes[t].user)
            self.send_email(t, email)
            events.append((t, "sent_link_phishing", email.link))
            sig = self.sig.scan_email(email)
            score, reasons = self.heur.score_email(email)
            if sig:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
                events.append((t, "detected_by_signature", sig))
            elif score >= 0.7:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
                events.append((t, "detected_by_heuristic", reasons))

            if random.random() < click_rate:
                # Simulate visiting link; we model behavior but do not do network calls
                result = self._simulate_link_visit(t, email.link)
                events.append((t, "link_visited", result))
        return events

    def _simulate_attachment_execution(self, node_id: str, doc: Document) -> str:
        node = self.nodes[node_id]
        # Signature check on document
        sig = self.sig.scan_document(doc)
        if sig:
            node.detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
            return f"blocked_by_signature:{sig}"
        # Heuristic check
        score, reasons = self.heur.score_email(Email(sender="unknown", recipient=node.user, subject="", body="", attachment=doc))
        if score > 0.8:
            node.detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
            return f"blocked_by_heuristic:{reasons}"

        # "Execute" macro: interpret macro_behavior in a descriptive, non-destructive way
        if doc.has_macro and doc.macro_behavior:
            behavior = doc.macro_behavior
            # Map descriptive behaviors to safe simulated effects
            if behavior == "exfiltrate_simulated_credentials":
                # Simulate credential theft by marking node as compromised and storing a marker
                node.compromised = True
                node.compromise_vector = "malicious_macro_attachment"
                node.files.append(Document(name="creds_leak_marker.txt", content="SIMULATED: stolen-creds"))
                return "macro_executed:exfiltrate_simulated_credentials"
            elif behavior == "drop_ransom_note":
                node.compromised = True
                node.compromise_vector = "ransom_note_macro"
                return "macro_executed:drop_ransom_note"
            else:
                # Unknown macro behavior — mark as suspicious
                node.detection_alerts.append({"time": self.time, "type": "suspicious_macro", "detail": behavior})
                return f"macro_executed:unknown_behavior:{behavior}"
        return "no_macro_or_no_action"

    def _simulate_link_visit(self, node_id: str, link: str) -> str:
        node = self.nodes[node_id]
        # Signature check (domain-based)
        if "bad.example" in (link or ""):
            # Simulate drive-by 'exploit' leading to compromise with some probability
            if random.random() < 0.6:
                node.compromised = True
                node.compromise_vector = "drive_by_link"
                node.files.append(Document(name="drive_by_marker.txt", content="SIMULATED: drive-by compromise"))
                return "compromised_by_drive_by"
            else:
                node.detection_alerts.append({"time": self.time, "type": "suspicious_link_visit", "detail": link})
                return "suspicious_link_but_not_compromised"
        return "safe_link_or_unknown_behavior"

    # Simple propagation model for compromised nodes (very conservative and simulated)
    def propagate(self, propagation_chance: float = 0.05):
        events = []
        compromised_nodes = [n for n in self.nodes.values() if n.compromised]
        for node in compromised_nodes:
            # Each compromised node attempts to send phishing emails to others (simulated later)
            targets = [n for n in self.nodes.values() if not n.compromised and n.id != node.id]
            # choose up to 2 random targets to avoid explosive spread in the sim
            for target in random.sample(targets, min(2, len(targets))):
                # attacker-forged email from this compromised node (internal spearphish)
                subj = "Invoice follow-up"
                body = "Please see attached document."
                # create a "malicious" doc but with lower potency to simulate internal spread
                doc = Document(name=f"fwd_{random.randint(10,99)}.docm", content="forwarded doc", has_macro=True, macro_behavior="exfiltrate_simulated_credentials")
                email = Email(sender=node.user, recipient=target.user, subject=subj, body=body, attachment=doc)
                target.receive_email(email)
                events.append((node.id, "propagated_to", target.id))
        return events

    # Reporting utilities
    def summary(self) -> Dict:
        s = {
            "time": self.time,
            "total_nodes": len(self.nodes),
            "compromised": [n.id for n in self.nodes.values() if n.compromised],
            "alerts": {n.id: n.detection_alerts for n in self.nodes.values() if n.detection_alerts},
        }
        return s

# ----------------------------- CLI & Runner -----------------------------

def run_demo(sim_rounds: int = 3, num_nodes: int = 10, seed: Optional[int] = None):
    sim = Simulator(num_nodes=num_nodes, seed=seed)

    # initial baseline: number of messages per user = 1 (for illustrative anomaly detection)
    for n in sim.nodes.values():
        sim.ano.update_baseline(n.user, 1)

    log_events = []

    for r in range(sim_rounds):
        sim.time += 1
        print(f"\n=== Simulation round {r+1} (time={sim.time}) ===")

        # Phase 1: attacker sends phishing to a random subset
        targets = random.sample(list(sim.nodes.keys()), max(1, len(sim.nodes)//3))
        events = sim.simulate_phishing_campaign(targets, lure=random.choice(["invoice", "payment", "receipt"]), click_rate=0.3)
        for e in events:
            log_events.append({"time": sim.time, "event": e})

        # Phase 2: link-based campaign
        targets2 = random.sample(list(sim.nodes.keys()), max(1, len(sim.nodes)//4))
        events = sim.simulate_link_campaign(targets2, click_rate=0.2)
        for e in events:
            log_events.append({"time": sim.time, "event": e})

        # Phase 3: propagation from compromised nodes
        events = sim.propagate(propagation_chance=0.05)
        for e in events:
            log_events.append({"time": sim.time, "event": e})

        # Print round summary
        s = sim.summary()
        print(f"Compromised nodes so far: {s['compromised']}")
        if s.get("alerts"):
            print("Alerts:")
            for nid, alerts in s["alerts"].items():
                print(f"  - {nid}: {alerts}")

    # Final report
    final = sim.summary()
    print("\n=== Final Summary ===")
    print(json.dumps(final, indent=2))

    # Optionally write a CSV log for offline analysis (safe textual events only)
    with open("sim_events_log.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["time", "node", "action", "detail"])
        for rec in log_events:
            t = rec["time"]
            node, action, detail = rec["event"]
            writer.writerow([t, node, action, json.dumps(detail)])

    print("Wrote sim_events_log.csv (safe, descriptive events)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email & Document Virus Simulator (safe educational)")
    parser.add_argument("--rounds", type=int, default=4, help="Number of simulation rounds")
    parser.add_argument("--nodes", type=int, default=12, help="Number of simulated endpoints/nodes")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    run_demo(sim_rounds=args.rounds, num_nodes=args.nodes, seed=args.seed)
