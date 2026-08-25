from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.detection.ml_fusion import apply_ml_signal
from src.detection.scoring import score_process, ProcessScore
from src.intelligence.network_ioc import NetworkIOCMatcher, load_network_indicators
from src.intelligence.osint_loader import load_mining_indicators, load_allowlisted_processes
from src.ml.model_registry import load_model


@dataclass
class EvaluationScenario:
    id: int
    name: str
    description: str
    process: ProcessInfo
    network: Optional[ProcessNetworkInfo]
    expected: str
    is_persistence_case: bool = False
    notes: str = ""


def build_evaluation_scenarios() -> List[EvaluationScenario]:
    """Define the 10 controlled evaluation scenarios representing diverse benign and malicious workloads."""
    return [
        EvaluationScenario(
            id=1,
            name="Normal Windows workload",
            description="Explorer desktop shell performing standard baseline OS operations with minimal resource consumption.",
            process=ProcessInfo(
                pid=101,
                name="explorer.exe",
                path=r"C:\Windows\explorer.exe",
                cmdline="explorer.exe",
                cpu_percent=2.0,
                memory_percent=4.0,
            ),
            network=None,
            expected="BENIGN",
            notes="Legitimate Windows shell process running from System directory.",
        ),
        EvaluationScenario(
            id=2,
            name="High CPU legitimate workload",
            description="Video rendering application utilizing multi-threaded CPU without mining indicators or suspicious network calls.",
            process=ProcessInfo(
                pid=102,
                name="video_render.exe",
                path=r"C:\Program Files\VideoStudio\video_render.exe",
                cmdline="video_render.exe --threads 8 --render-output out.mp4",
                cpu_percent=85.0,
                memory_percent=15.0,
            ),
            network=None,
            expected="BENIGN/LOW",
            notes="Legitimate high CPU usage alone should not trigger false cryptojacking alerts.",
        ),
        EvaluationScenario(
            id=3,
            name="Simulated CPU miner",
            description="Standard XMRig standalone CPU miner connecting to external mining pool.",
            process=ProcessInfo(
                pid=103,
                name="xmrig.exe",
                path=r"C:\Users\User\Downloads\xmrig.exe",
                cmdline="xmrig.exe --url=stratum+tcp://pool:3333 --user=48edfXzk --pass=x",
                cpu_percent=95.0,
                memory_percent=10.0,
            ),
            network=ProcessNetworkInfo(
                pid=103,
                local_ports=[50000],
                remote_ports=[3333],
                remote_addresses=["pool.minexmr.com:3333"],
                statuses=["ESTABLISHED"],
            ),
            expected="HIGH",
            notes="Known miner binary name + CLI stratum indicators + Stratum port 3333 + 95% CPU.",
        ),
        EvaluationScenario(
            id=4,
            name="Miner-like CLI + high CPU",
            description="Obfuscated / unknown executable spawned from user temp directory with cryptocurrency mining arguments.",
            process=ProcessInfo(
                pid=104,
                name="unknown.exe",
                path=r"C:\Users\User\AppData\Local\Temp\unknown.exe",
                cmdline="unknown.exe --algo randomx --coin xmr -o pool.supportxmr.com:3333",
                cpu_percent=80.0,
                memory_percent=8.0,
            ),
            network=None,
            expected="HIGH",
            notes="Suspicious writable path + RandomX mining algorithms + multiple mining CLI flags.",
        ),
        EvaluationScenario(
            id=5,
            name="Miner + mining network IOC",
            description="Dedicated mining tool establishing network communication with known cryptocurrency mining pool endpoints.",
            process=ProcessInfo(
                pid=105,
                name="miner.exe",
                path=r"C:\tools\miner.exe",
                cmdline="miner.exe --pool stratum+tcp://pool.com:3333 -u wallet_address",
                cpu_percent=90.0,
                memory_percent=12.0,
            ),
            network=ProcessNetworkInfo(
                pid=105,
                local_ports=[50001],
                remote_ports=[3333],
                remote_addresses=["192.168.1.100:3333"],
                statuses=["ESTABLISHED"],
            ),
            expected="VERY HIGH",
            notes="Correlated multi-vector evidence: mining name + CLI + Stratum protocol port 3333.",
        ),
        EvaluationScenario(
            id=6,
            name="Masqueraded process",
            description="System lookalike binary svchost.exe executing out of user-writable Temp folder instead of System32.",
            process=ProcessInfo(
                pid=106,
                name="svchost.exe",
                path=r"C:\Users\Temp\svchost.exe",
                cmdline="svchost.exe -k netsvcs",
                cpu_percent=75.0,
                memory_percent=10.0,
            ),
            network=None,
            expected="HIGH",
            notes="Masquerading system process path anomaly combined with suspicious high CPU consumption.",
        ),
        EvaluationScenario(
            id=7,
            name="Persistence + miner evidence",
            description="Mining updater registered in persistence mechanisms running with mining flags.",
            process=ProcessInfo(
                pid=107,
                name="updater.exe",
                path=r"C:\Users\User\AppData\Roaming\updater.exe",
                cmdline="updater.exe --algo randomx --pool pool.minexmr.com",
                cpu_percent=80.0,
                memory_percent=8.0,
            ),
            network=None,
            expected="HIGH",
            is_persistence_case=True,
            notes="Combines RandomX mining args with simulated registry run key persistence finding.",
        ),
        EvaluationScenario(
            id=8,
            name="Browser sustained CPU + mining IOC",
            description="Web browser process executing in-browser JavaScript miner connecting to a mining pool endpoint.",
            process=ProcessInfo(
                pid=108,
                name="chrome.exe",
                path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                cmdline="chrome.exe --type=renderer --site-per-process",
                cpu_percent=60.0,
                memory_percent=14.0,
            ),
            network=ProcessNetworkInfo(
                pid=108,
                local_ports=[54321],
                remote_ports=[3333],
                remote_addresses=["pool.minexmr.com:3333"],
                statuses=["ESTABLISHED"],
            ),
            expected="HIGH",
            notes="Browser process exhibiting sustained compute paired with outbound Stratum pool connection.",
        ),
        EvaluationScenario(
            id=9,
            name="False-positive Java server",
            description="Enterprise backend web server under load listening on standard HTTP application port 8080.",
            process=ProcessInfo(
                pid=109,
                name="java.exe",
                path=r"C:\Program Files\Java\jdk-17\bin\java.exe",
                cmdline="java.exe -jar spring-boot-app.jar --server.port=8080",
                cpu_percent=90.0,
                memory_percent=25.0,
            ),
            network=ProcessNetworkInfo(
                pid=109,
                local_ports=[8080],
                remote_ports=[8080],
                remote_addresses=["10.0.0.5:8080"],
                statuses=["LISTEN"],
            ),
            expected="BENIGN",
            notes="High CPU and high memory server workloads without mining IOCs should remain benign.",
        ),
        EvaluationScenario(
            id=10,
            name="Normal Chrome high CPU",
            description="Standard web browser rendering high-resolution 4K streaming video over standard HTTPS port 443.",
            process=ProcessInfo(
                pid=110,
                name="chrome.exe",
                path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                cmdline="chrome.exe --type=renderer https://www.youtube.com/watch?v=4kvideo",
                cpu_percent=85.0,
                memory_percent=18.0,
            ),
            network=ProcessNetworkInfo(
                pid=110,
                local_ports=[51234],
                remote_ports=[443],
                remote_addresses=["142.250.190.46:443"],
                statuses=["ESTABLISHED"],
            ),
            expected="BENIGN/LOW",
            notes="Legitimate browser multimedia decoding de-emphasized via allowlist heuristics.",
        ),
    ]


def evaluate_scenarios() -> Dict[str, Any]:
    """Execute all evaluation scenarios through the hybrid detection pipeline."""
    config_path = PROJECT_ROOT / "config.json"
    data_dir = PROJECT_ROOT / "data"
    model_path = PROJECT_ROOT / "models" / "rf_cryptojack_model.pkl"

    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        config = {}

    indicators: Set[str] = load_mining_indicators(data_dir / "mining_iocs.txt")
    allowlist_names: Set[str] = load_allowlisted_processes(data_dir / "allowlist_processes.txt")
    config["allowlist_process_names"] = list(allowlist_names)

    network_ips, network_domains = load_network_indicators(str(data_dir / "mining_network_iocs.txt"))
    network_ioc_matcher = NetworkIOCMatcher(network_ips, network_domains)

    try:
        ml_model = load_model(model_path)
    except Exception as exc:
        print(f"[!] Warning: Could not load ML model ({exc}). Proceeding with heuristic only.")
        ml_model = None

    scenarios = build_evaluation_scenarios()
    results: List[Dict[str, Any]] = []

    passed_count = 0
    total_count = len(scenarios)

    for sc in scenarios:
        score_obj: ProcessScore = score_process(
            sc.process,
            sc.network,
            indicators,
            config,
            network_ioc_matcher,
        )

        if ml_model is not None:
            apply_ml_signal(score_obj, sc.process, sc.network, ml_model)

        if sc.is_persistence_case:
            score_obj.risk_score = min(100.0, score_obj.risk_score + 15.0)
            score_obj.reasons.append("persistence finding: user startup registry key detected")

        # Determine verification pass / fail status
        if sc.expected in ("BENIGN", "BENIGN/LOW"):
            passed = score_obj.risk_score < 40.0
            actual_classification = "BENIGN (Low Risk)" if score_obj.risk_score < 40.0 else "MALICIOUS (False Positive)"
        elif sc.expected == "VERY HIGH":
            passed = score_obj.risk_score >= 80.0
            actual_classification = "VERY HIGH RISK" if score_obj.risk_score >= 80.0 else "INSUFFICIENT RISK"
        else:  # HIGH
            passed = score_obj.risk_score >= 60.0
            actual_classification = "HIGH RISK" if score_obj.risk_score >= 60.0 else "INSUFFICIENT RISK"

        if passed:
            passed_count += 1

        results.append({
            "id": sc.id,
            "name": sc.name,
            "proc_name": sc.process.name,
            "cpu": sc.process.cpu_percent,
            "ml_confidence": score_obj.ml_confidence,
            "risk_score": score_obj.risk_score,
            "expected": sc.expected,
            "actual_classification": actual_classification,
            "passed": passed,
            "reasons": list(score_obj.reasons),
            "notes": sc.notes,
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": total_count,
        "passed": passed_count,
        "accuracy": (passed_count / total_count) * 100.0,
        "results": results,
    }


def generate_markdown_report(evaluation: Dict[str, Any]) -> str:
    """Generate the structured academic thesis evaluation report in Markdown format."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = [
        "# CryptoJackGuard: Thesis Evaluation & Controlled Scenario Report",
        "",
        f"**Generated on:** {now_str}  ",
        f"**Evaluation Summary:** {evaluation['passed']} / {evaluation['total']} Scenarios Passed ({evaluation['accuracy']:.1f}% Accuracy)  ",
        "",
        "## Executive Summary",
        "",
        "This evaluation report validates the detection fidelity, heuristic scoring, machine learning inference, and false-positive suppression capabilities of the **CryptoJackGuard** defense prototype across 10 controlled workload scenarios.",
        "",
        "## Scenario Results Matrix",
        "",
        "| # | Scenario | Process Name | CPU % | ML Confidence | Final Risk Score | Expected | Actual Status |",
        "|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|",
    ]

    for item in evaluation["results"]:
        status_badge = "**PASS**" if item["passed"] else "**FAIL**"
        lines.append(
            f"| {item['id']} | {item['name']} | `{item['proc_name']}` | {item['cpu']:.1f}% | {item['ml_confidence']*100.0:.1f}% | {item['risk_score']:.1f} | {item['expected']} | {status_badge} |"
        )

    lines.extend([
        "",
        "## Detailed Scenario Findings",
        "",
    ])

    for item in evaluation["results"]:
        status_icon = "[PASS]" if item["passed"] else "[FAIL]"
        lines.extend([
            f"### Scenario {item['id']}: {item['name']} {status_icon}",
            f"- **Target Process:** `{item['proc_name']}` (CPU: {item['cpu']:.1f}%)",
            f"- **Expected Classification:** `{item['expected']}`",
            f"- **Final Computed Risk Score:** `{item['risk_score']:.1f}/100.0` (ML Confidence: `{item['ml_confidence']*100.0:.1f}%`)",
            f"- **Outcome:** {item['actual_classification']}",
            "- **Triggered Evidence / Reasons:**",
        ])
        if item["reasons"]:
            for r in item["reasons"]:
                lines.append(f"  - {r}")
        else:
            lines.append("  - None (Normal baseline execution)")
        lines.append(f"- **Scenario Context & Notes:** {item['notes']}")
        lines.append("")

    lines.extend([
        "## Evaluation Methodology & Thresholds",
        "",
        "- **Benign / Legitimate Threshold:** Risk Score < 40.0 (No alert generated, system monitoring continues passively).",
        "- **Elevated Suspicion Threshold:** 40.0 <= Risk Score < 60.0 (Telemetry logged, deep inspection initiated).",
        "- **Alert / Mitigation Threshold:** Risk Score >= 60.0 (High-risk confirmation, automated cooldown management, and safe response prompted).",
        "- **Critical Alert Threshold:** Risk Score >= 80.0 (Multi-vector confirmation combining ML inference, Stratum network telemetry, and CPU load).",
        "",
        "---",
        "*Report generated automatically by CryptoJackGuard Thesis Evaluation Framework.*",
    ])

    return "\n".join(lines)


def main() -> int:
    """Run the evaluation, save the report, and print the summary to console."""
    print("=" * 70)
    print("CryptoJackGuard: Executing Controlled Thesis Evaluation Scenarios...")
    print("=" * 70)

    evaluation = evaluate_scenarios()
    report_md = generate_markdown_report(evaluation)

    docs_dir = PROJECT_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    report_path = docs_dir / "thesis_evaluation_report.md"

    with report_path.open("w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"[+] Evaluation Report successfully written to: {report_path}")
    print("\n" + report_md + "\n")
    print("=" * 70)
    print(f"Final Result: {evaluation['passed']} / {evaluation['total']} Scenarios Passed ({evaluation['accuracy']:.1f}%)")
    print("=" * 70)

    return 0 if evaluation["passed"] == evaluation["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
