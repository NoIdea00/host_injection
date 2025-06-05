# 🚀 Host Header Injection Scanner

A powerful multi-threaded Python script designed to scan a list of targets for open ports using `Naabu` and then perform `Curl` tests, specifically looking for potential Host Header Injection vulnerabilities. The tool features robust state management, allowing scans to be resumed even after interruptions.

## ✨ Features

* **Multi-threaded Scanning:** Efficiently processes multiple targets concurrently.
* **State Management:** Automatically saves scan progress and can resume from the last known state after interruptions (e.g., `Ctrl+C`, system crash).
* **Naabu Integration:** Leverages `Naabu` for fast and reliable port scanning.
* **Curl Testing:** Performs HTTP/S requests on identified open ports (80, 8080 by default).
* **Host Header Injection Detection:** Attempts to identify Host Header Injection opportunities by observing `Curl` responses when a custom host header is injected.
* **Comprehensive Logging:** Detailed activity logs are stored in a JSONL format.
* **Configurable:** Easily adjust worker threads, host header overrides, and more.
* **Output Summaries:** Generates individual run summaries and a master summary of all successful results.

## ⚙️ Prerequisites

Before running the script, ensure you have the following installed:

* **Python 3.x** (recommended Python 3.8+)
* **Naabu**: A fast port scanner.
    * Installation instructions: [Naabu GitHub](https://github.com/projectdiscovery/naabu#installation)
* **Curl**: A command-line tool for transferring data with URLs.
    * Usually pre-installed on Linux/macOS. For Windows, download from [Curl website](https://curl.se/windows/).

## ⬇️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/NoIdea00/host_injection.git
    cd your-repo-name
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: `venv\Scripts\activate`
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Usage

1.  **Prepare your target list:** Create a text file (e.g., `targets.txt`) with one IP address or domain per line.
    ```
    example.com
    192.168.1.1
    sub.domain.com
    # You can also add comments with '#'
    ```

2.  **Run the scanner:**
    ```bash
    python3 host_injection_v3.py -l targets.txt -w 20 -v -H google.com
    ```

    **Command-line Arguments:**
    * `-l, --list <file_path>`: **(Required)** Path to the list of targets (IPs or domains).
    * `-w, --workers <number>`: Number of concurrent worker threads (default: `10`).
    * `-v, --verbose`: Enable verbose output to the console.
    * `-H, --host-header <header_value>`: Host header override for Curl tests (default: `google.com`).

    **Example:**
    ```bash
    # Scan targets from 'my_targets.txt' with 15 workers, verbose output,
    # and 'evil.com' as the host header override.
    python3 host_injection_v3.py -l my_targets.txt -w 15 -v -H evil.com

    # Resume a previous scan from 'resume_targets.txt' with default settings
    # (state will automatically load if available)
    python3 host_injection_v3.py -l resume_targets.txt
    ```

## 📊 Output Structure

All scan results, state files, and logs are stored in the `results/` directory:


```
results/
├── naabu_locks/              # 🔒 Temporary lock files for active Naabu scans
├── host_injection_result/    # 🎯 Files detailing potential host header injection opportunities
├── run_summaries/            # 📝 Individual JSON summaries for each processed target
├── master_summary/           # 📜 Final aggregated JSON summary of all findings
├── state/                    # 💾 Stores scan state for resumption and backups
└── logs/                     # 📄 scan_activity.jsonl contains detailed logs of all operations
```

## 🛠️ Configuration

You can modify several configuration constants directly within the `host_injection_v3.py` script:

* `SAVE_INTERVAL`: Interval (in seconds) for periodic state saving (default: 1800 seconds / 30 minutes).
* `MAX_BACKUPS`: Maximum number of state backups to keep (default: 5).
* `BASE_DIR`: Base directory for all scan outputs (default: `results`).
* `HOST_HEADER`: Default host header used for Curl tests if not overridden via `-H` (default: `google.com`).
* `ALLOWED_PORTS`: A set of ports for which Curl checks will be performed after Naabu identifies them as open (default: `{"80", "8080"}`).
* `MAX_RETRIES`: Number of retries for failed Curl checks (default: 2).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
