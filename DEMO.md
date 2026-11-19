# Demo

A short walkthrough of the tool running end to end.

## Record a short demo (2 to 3 minutes)
Show these steps on screen (a screen recording, or a few clear screenshots):

1. Install and configure:
   ```
   pip install -r requirements.txt
   export QWEN_BASE_URL="http://your-server:8000/v1"
   export QWEN_API_KEY="your-api-key"
   ```
2. Show the help so viewers see the options:
   ```
   python logtriage.py --help
   ```
3. Run it on a real log and generate a rule:
   ```
   python logtriage.py --input ssh_auth_log.txt --output results.csv --rule sigma --rule-out rule.txt
   ```
4. Open `results.csv` and `rule.txt` to show the output.
5. Run the tests to show they pass:
   ```
   python -m pytest
   ```
6. Run the Semgrep static analysis scan:
   ```
   semgrep scan --config auto logtriage.py
   ```

## Example run

```
$ python logtriage.py --input ssh_auth_log.txt --rule sigma --rule-out rule.txt
Connected. Model: Qwen/Qwen2.5-Coder-7B-Instruct
Assessing 200 entries from ssh_auth_log.txt ...
  BENIGN     121
  SUSPICIOUS  58
  MALICIOUS   21
Wrote triage_results.csv
Wrote rule.txt
```

Put your recording link (or screenshots) here, plus one or two sentences about
what the tool does and what you would improve next.
