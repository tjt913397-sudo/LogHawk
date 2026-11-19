# LogHawk — Application Demonstration
 
## Overview

LogHawk is a Python command-line security log triage application that uses Qwen to classify log entries as BENIGN, SUSPICIOUS, or MALICIOUS. It can export analysis results to CSV and JSON and generate Sigma detection rules.

## Demonstration Method

This demonstration uses screenshots of successful application execution, unit testing, and security analysis.

## 1. Command-Line Interface

Command:

```bash
python logtriage.py --help
```

The application displays its available arguments, including input files, output formats, batch limits, worker counts, and Sigma rule generation.

**Evidence:** Lab 7 Screenshot 1.

## 2. End-to-End Log Analysis

Command:

```bash
python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json --limit 3 --max-workers 2 --rule sigma --rule-out rule.txt
```

Model: `qwen3.5-122b-a10b`

Verified results:

- Entries analyzed: 3
- BENIGN: 2
- SUSPICIOUS: 1
- MALICIOUS: 0

Generated files: `results.csv`, `results.json`, and `rule.txt`.

**Evidence:** Lab 7 Screenshot 2.

## 3. Sigma Detection Rule

Command:

```bash
cat rule.txt
```

LogHawk generated a Sigma-style detection rule identifying failed SSH password authentication attempts.

**Evidence:** Lab 7 Screenshot 3.

## 4. Automated Unit Tests

Command:

```bash
python -m pytest -v test_logtriage.py
```

Result: All five unit tests passed.

**Evidence:** Lab 7 Screenshot 4.

## 5. Security Analysis

Command:

```bash
semgrep scan --config auto logtriage.py
```

Result: Semgrep scanned one Python file using 290 rules and reported zero findings.

**Evidence:** Lab 7 Screenshot 5.

## 6. Continuous Integration

GitHub Actions automatically runs pytest and Semgrep when changes are pushed to the repository.

The `test-and-scan` job completed successfully.

**Evidence:** Lab 7 Screenshot 6.

## Repository

https://github.com/tjt913397-sudo/LogHawk

## Future Improvements

Future improvements include validating generated Sigma rules against the Sigma specification, improving rule metadata, and optimizing model response times for larger log datasets.

The demonstration used three log entries because the Qwen server had previously experienced long response times. A complete 200-entry analysis remains a potential additional test.
