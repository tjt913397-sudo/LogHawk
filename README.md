# &lt;LogHawk&gt;

An AI-powered **security log triage** command-line tool. It reads a security log
file and uses a coding language model (Qwen Coder, or any OpenAI-compatible
model) to classify each entry as **BENIGN**, **SUSPICIOUS**, or **MALICIOUS**,
with a severity (1&ndash;5) and a one-sentence reason. It processes a whole file
in parallel, saves the results, and can generate a detection rule from what it
finds.

_Capstone project for IS2083 Advanced Scripting (combines Labs 5 and 6)._

## Features
- Classifies each log entry with a label, a 1&ndash;5 severity, and a reason.
- Returns validated JSON and falls back safely on bad output.
- Processes a whole log file in batch, one bad line never stops the run.
- Generates a detection rule (Sigma, iptables, or regex) from the findings.
- Treats log text as untrusted input and uses a hardened prompt to resist prompt injection.
- Ships with offline tests and a CI workflow.

## Requirements
- Python 3.9 or newer
- The `openai` package: `pip install -r requirements.txt`
- Access to an OpenAI-compatible model endpoint (a vLLM server, the class Qwen Coder server, etc.)

## Setup
```
pip install -r requirements.txt
export QWEN_BASE_URL="http://your-server:8000/v1"
export QWEN_API_KEY="your-api-key"
```
On Windows PowerShell use `setx` or `$env:QWEN_BASE_URL="..."` instead of `export`.

## Usage
```
python logtriage.py --input security_log.txt
python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json
python logtriage.py --input ssh_auth_log.txt --rule sigma --rule-out rule.txt
```
See all options with:
```
python logtriage.py --help
```

## Testing
The tests use a fake model, so they run with no server and no key:
```
pip install -r requirements.txt
python -m pytest
```

## Static analysis (Semgrep)
Semgrep reads the code without running it and reports security issues and risky
patterns (SAST):
```
semgrep scan --config auto logtriage.py
```
The CI workflow runs both the tests and Semgrep on every push.

## Security notes
- The API key is read from an environment variable; it is never hard-coded or committed.
- Log data is treated as untrusted; a hardened prompt resists instructions hidden in the input.

## License
MIT &mdash; see the `LICENSE` file.
