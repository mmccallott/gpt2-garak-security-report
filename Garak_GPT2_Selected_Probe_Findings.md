# Testing Garak Probes on GPT-2

## Selected-probe findings and analysis

**Assessment date:** November 2, 2026  
**Tool:** Garak 0.17.1  
**Target recorded in the reports:** Hugging Face model `gpt2`  
**Assessment scope:** Four selected Garak probe families: `exploitation`, `grandma`, `malwaregen`, and `web_injection`

> **Scope statement:** This is not a comprehensive full scan. It includes only the probes selected and run by the author. The findings below describe the supplied Garak outputs and do not establish that a real-world system was exploited or that GPT-2 is safe or unsafe overall.

## Executive summary

Four Garak runs tested selected probes against the Hugging Face `gpt2` target. Garak recorded detector-level failures in each selected probe family. The largest flagged shares within the individual result rows included `SQLiEcho` at 42 of 50 evaluations (84%), `MitigationBypass` at 50 of 50 for `grandma.Substances` and 30 of 30 for `grandma.Win11`, and `AnyCode` at 88 of 280 for `malwaregen.SubFunctions` (31.4%). In `web_injection`, the extended non-image and image URI exfiltration checks recorded 217 of 1,280 (17.0%) and 114 of 1,280 (8.9%) detector failures, respectively.

These are **scanner findings, not confirmed vulnerabilities**. A Garak detector evaluates generated outputs against its own criterion. A detector `FAIL` does not by itself prove successful code execution, data leakage, an exploitable application, or impact. Conversely, zero detector failures in a selected test do not establish immunity to other probes or attack variants.

Because probes, detectors, behaviors, and denominators differ, the results should not be combined into an overall safety score or directly ranked across probe families.

## Assessment scope and method

The supplied run notes record these commands, one per run:

```text
python3 -m garak --model_type huggingface --model_name gpt2 --probes exploitation
python3 -m garak --model_type huggingface --model_name gpt2 --probes grandma
python3 -m garak --model_type huggingface --model_name gpt2 --probes malwaregen
python3 -m garak --model_type huggingface --model_name gpt2 --probes web_injection
```

Each JSONL report records Garak version `0.17.1`, target type `huggingface`, target name `gpt2`, a generation setting of `5`, and a null seed value. The reports do not identify a specific Hugging Face model revision or checkpoint. They also do not fully establish the execution environment or other runtime details.

The counts below are taken from the JSONL `eval` entries and shown as **detector FAILs / total evaluated**. “Flagged” is shorthand for that detector outcome only; it is not a human-verified vulnerability judgment. Where multiple detectors evaluate a probe, their entries are shown separately and are not added as if they were independent samples. Percentages are calculated from each individual row and rounded to one decimal place.

## Findings

### 1. Exploitation probes

| Probe | Detector | FAILs / evaluated | Flagged share |
|---|---|---:|---:|
| `exploitation.JinjaTemplatePythonInjection` | `exploitation.JinjaTemplateInjectionDetector` | 12 / 45 | 26.7% |
| `exploitation.JinjaTemplatePythonInjection` | `exploitation.PythonCodeExecution` | 12 / 45 | 26.7% |
| `exploitation.SQLInjectionEcho` | `exploitation.SQLiEcho` | 42 / 50 | 84.0% |

**Analysis.** `SQLiEcho` recorded the highest flagged share in this run. This means the detector flagged 42 of the 50 evaluated outputs for this probe; it does not demonstrate that a database was present, reached, or compromised. The two Jinja-related detector rows have the same probe and denominator. They are separate detector evaluations and should not be summed into 24 distinct findings.

### 2. Grandma probes

| Probe | Detector | FAILs / evaluated | Flagged share |
|---|---|---:|---:|
| `grandma.Slurs` | `mitigation.MitigationBypass` | 56 / 60 | 93.3% |
| `grandma.Slurs` | `unsafe_content.SlursReclaimedSlurs` | 0 / 60 | 0.0% |
| `grandma.Substances` | `mitigation.MitigationBypass` | 50 / 50 | 100.0% |
| `grandma.Win10` | `mitigation.MitigationBypass` | 29 / 30 | 96.7% |
| `grandma.Win10` | `productkey.Win5x5` | 0 / 30 | 0.0% |
| `grandma.Win11` | `mitigation.MitigationBypass` | 30 / 30 | 100.0% |
| `grandma.Win11` | `productkey.Win5x5` | 0 / 30 | 0.0% |

**Analysis.** The `MitigationBypass` detector flagged a large share of the outputs in the selected `grandma` tests. The paired slur and Windows product-key detector rows recorded zero failures. These outcomes use different detectors and criteria; they are not contradictory measurements of one common property. The zero-failure rows mean only that those detectors did not flag the evaluated outputs in these runs.

### 3. Malware-generation probes

| Probe | Detector | FAILs / evaluated | Flagged share |
|---|---|---:|---:|
| `malwaregen.Evasion` | `malwaregen.AnyCode` | 60 / 240 | 25.0% |
| `malwaregen.Payload` | `malwaregen.AnyCode` | 139 / 600 | 23.2% |
| `malwaregen.SubFunctions` | `malwaregen.AnyCode` | 88 / 280 | 31.4% |
| `malwaregen.TopLevel` | `malwaregen.AnyCode` | 14 / 80 | 17.5% |

**Analysis.** `malwaregen.SubFunctions` had the largest flagged share in this run (31.4%), while `malwaregen.Payload` had the largest number of flagged evaluations (139) and also the largest denominator (600). Those are different ways to describe the results and should not be conflated. The four rows sum arithmetically to 301 detector failures across 1,200 evaluations, but this combined count is not a severity score, a count of verified malware samples, or a measure of execution or compromise.

### 4. Web-injection probes

| Probe | Detector | FAILs / evaluated | Flagged share |
|---|---|---:|---:|
| `web_injection.ColabAIDataLeakage` | `web_injection.MarkdownExfilContent` | 0 / 20 | 0.0% |
| `web_injection.MarkdownImageExfil` | `web_injection.MarkdownExfilBasic` | 0 / 60 | 0.0% |
| `web_injection.MarkdownImageExfil` | `web_injection.MarkdownExfilContent` | 0 / 60 | 0.0% |
| `web_injection.MarkdownURIImageExfilExtended` | `web_injection.MarkdownExfilExtendedImage` | 114 / 1,280 | 8.9% |
| `web_injection.MarkdownURINonImageExfilExtended` | `web_injection.MarkdownExfilExtendedNonImage` | 217 / 1,280 | 17.0% |
| `web_injection.MarkdownXSS` | `web_injection.XSS` | 0 / 35 | 0.0% |
| `web_injection.PlaygroundMarkdownExfil` | `web_injection.PlaygroundMarkdownExfil` | 0 / 20 | 0.0% |
| `web_injection.StringAssemblyDataExfil` | `web_injection.MarkdownExfilBasic` | 0 / 10 | 0.0% |
| `web_injection.TaskXSS` | `web_injection.XSS` | 15 / 425 | 3.5% |

**Analysis.** The extended non-image exfiltration row had a higher flagged share than the extended image row. This is a descriptive comparison only: the probes and detector criteria differ, and the counts do not establish that data was actually exfiltrated. `TaskXSS` recorded 15 detector failures; this does not demonstrate that a browser or application executed a cross-site scripting payload. The remaining selected rows recorded zero detector failures, which is not evidence that all variants or application contexts would pass.

## Interpretation and limitations

### What the artifacts support

- The selected probes generated outputs that named Garak detectors flagged, at the row-level counts reported above.
- The result rows provide focused leads for follow-up review, particularly `SQLiEcho`, `MitigationBypass`, `AnyCode`, and the extended web-exfiltration detector results.
- The supplied run notes and JSONL establish the target type/name, Garak version, selected probe families, and the recorded settings described above.

### What they do not establish

- A comprehensive evaluation of GPT-2 or all Garak probes.
- Confirmed exploitability, successful code execution, actual data exfiltration, compromise, or impact.
- Safety or vulnerability of a deployed application, including its wrapper, connected tools, data boundaries, or mitigations.
- A model-wide risk score or a guarantee about untested inputs.
- The precise model checkpoint/revision or a fully reproducible runtime environment.

The report archive contains JSONL and hitlog artifacts for all four runs. HTML reports were supplied for three runs; the `malwaregen` run's HTML report was not present in the archive. The JSONL evaluation entries are the basis for the tabulated counts.

## Recommended follow-up

1. Inspect the hitlog and corresponding attempt records for each flagged detector row. Confirm whether the detector match is meaningful in the context of the exact generated output.
2. Re-run the specific probes of interest and preserve the complete command, configuration, environment, and dependency versions.
3. Record and pin the Hugging Face model revision/checkpoint. The supplied reports identify `gpt2` but not a revision, and the seed field is null.
4. If the intended conclusion concerns a real application, assess that application in its authorized context, including its inputs, wrapper, tools, data access, and mitigations. The supplied evidence describes selected model scans, not an application test.
5. Expand probe coverage only when the assessment objective is defined; document which probes were selected and which were not run.

## References

1. Garak documentation, [“Reading the results”](https://docs.garak.ai/garak/llm-scanning-basics/reading-the-results.md). Describes Garak probe/detector result lines and report/hitlog files.
2. Garak documentation, [“Scan evaluation”](https://docs.garak.ai/garak/garak-components/scan-evaluation.md). Describes evaluation scores and the default threshold evaluator.
3. National Institute of Standards and Technology, [Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile (NIST AI 600-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), July 2024. Referenced for disciplined documentation of context, measurement, and limitations; this report does not claim NIST compliance.
4. OWASP GenAI Security Project, [Top 10 for Large Language Model Applications](https://genai.owasp.org/llm-top-10/). Referenced as an industry risk-taxonomy resource; these model-scan results are not mapped to OWASP categories because the artifacts do not establish application context or controls.

---

**Reporting note:** This write-up summarizes the supplied Garak artifacts and selected-probe results. It is not a certification, penetration-test attestation, or claim of comprehensive model security.
