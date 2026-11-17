# LogHawk

LogHawk is an AI-powered security log analysis tool developed in Python for the IS2083 Advanced Scripting course at UTSA.

## Features

- Classifies security log entries as BENIGN, SUSPICIOUS, or MALICIOUS.
- Uses Qwen through GPUStack to analyze log activity.
- Returns structured results with severity scores and explanations.
- Processes multiple security log entries using batch processing.
- Exports results to CSV and JSON.
- Generates Sigma detection rules.
- Demonstrates prompt-injection attacks and defenses.
- Includes automated tests for JSON parsing and input validation.

## Requirements

- Python 3
- Jupyter Notebook or JupyterLab
- OpenAI Python library
- Access to a compatible Qwen API server and an API key

## How to Run

1. Download the Jupyter notebook from this repository.
2. Open it in JupyterLab.
3. Install the required Python library using `%pip install openai`.
4. Configure the Qwen API server address.
5. Enter your API key securely when prompted.
6. Run the notebook cells in order.
7. Upload a security log dataset to analyze.

## Project Status

Lab 6 extends the original Lab 5 project. The current saved batch results cover 10 log entries because the shared model server was responding slowly during testing.

## Security

API keys are entered using Python's `getpass` module and should never be committed to this repository.
