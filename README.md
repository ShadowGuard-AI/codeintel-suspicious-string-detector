![Banner](banner.png)

# codeintel-Suspicious-String-Detector
Scans code for potentially malicious or suspicious strings, such as those used in command injection or path traversal attacks. Flags strings based on regular expressions and entropy analysis. Focused on tools for static code analysis, vulnerability scanning, and code quality assurance.

## Install
`git clone https://github.com/ShadowGuard-AI/codeintel-suspicious-string-detector`

## Usage
`python3 main.py (-f FILE | -d DIRECTORY) [-e ENTROPY_THRESHOLD] [-l LOG_FILE]`

## Parameters
- `-h`: Show help message and exit
- `-f`, `--file`: Path to the file to scan. Exactly one of `-f` and `-d` is required.
- `-d`, `--directory`: Path to the directory to scan (recursively).
- `-e`, `--entropy_threshold`: Entropy threshold for detecting high-entropy strings (default: 4.5).
- `-l`, `--log_file`: Path to the log file. If not provided, logs will be printed to the console.

## Verified behavior
- A file containing a high-entropy string (entropy 4.57 in the test) and an `os.system` call is flagged for both, and the run exits 0.

## License
See LICENSE.
