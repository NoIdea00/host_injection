import argparse
import subprocess
import os
import sys
import signal
import threading
import json
import csv
import time
import socket
import re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from html import escape
import termios
import tty
import select
import shutil
import traceback

## =================== CONFIGURATION ===================
SAVE_INTERVAL = 1800
MAX_BACKUPS = 5

BASE_DIR = Path("results")
NAABU_LOCK_DIR = BASE_DIR / "naabu_locks"
INJECT_DIR = BASE_DIR / "host_injection_result"
RUN_SUMMARY_DIR = BASE_DIR / "run_summaries"
MASTER_SUMMARY_DIR = BASE_DIR / "master_summary"

STATE_DIR = BASE_DIR / "state"
LOG_DIR = BASE_DIR / "logs"
LOG_FILENAME = LOG_DIR / "scan_activity.jsonl"

# Ensure base folders exist
for d in [NAABU_LOCK_DIR, INJECT_DIR, RUN_SUMMARY_DIR, MASTER_SUMMARY_DIR, STATE_DIR, LOG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

LOCK_EXT = ".lock"
HOST_HEADER = "google.com"
ALLOWED_PORTS = {"80", "8080"}
MAX_RETRIES = 2
STATE_FILENAME_PREFIX = "scan_state"


# --- Globals ---
pause_flag = threading.Event()
pause_flag.set()
stop_flag = threading.Event()
general_file_lock = threading.RLock()

# =================== LOGGING ===================
def write_log_entry(level, message, **extra_data):
    """Appends a JSON log entry to the global log file."""
    with general_file_lock: # Keep this lock for logging to avoid log file corruption
        try:
            with open(LOG_FILENAME, 'a', encoding='utf-8') as f:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "level": level.upper(),
                    "message": message,
                    **extra_data
                }
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            print(f"CRITICAL_LOG_ERROR: Could not write to log file {LOG_FILENAME}: {e} :: Original log: {level} - {message} {extra_data}", file=sys.stderr)

# =================== SIGNAL HANDLERS ===================
def sigint_handler(sig, frame):
    write_log_entry("WARNING", "Ctrl+C detected. Signaling threads to stop.")
    print("\n[!] Ctrl+C detected. Signaling threads to stop...")
    stop_flag.set()
    pause_flag.set()
    print("[*] Exiting gracefully. Summary update will be attempted.")

signal.signal(signal.SIGINT, sigint_handler)

def sigtstp_handler(sig, frame):
    write_log_entry("INFO", "Ctrl+Z (SIGTSTP) pressed. Pausing scan.")
    print("\n[!] Ctrl+Z (SIGTSTP) pressed. Pausing scan...")
    pause_flag.clear()
    print("[*] Scan paused. You can resume with 'fg' command and then Ctrl+R, or 'kill -SIGCONT <pid>'.")
signal.signal(signal.SIGTSTP, sigtstp_handler)

def sigcont_handler(sig, frame):
    if not pause_flag.is_set():
        write_log_entry("INFO", "SIGCONT received. Resuming scan.")
        print("\n[!] SIGCONT received. Resuming scan...")
        pause_flag.set()
signal.signal(signal.SIGCONT, sigcont_handler)

# =================== THREAD TO HANDLE CTRL+P / CTRL+R ===================
def stdin_key_listener():
    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        if '--verbose' in sys.argv or '-v' in sys.argv:
             write_log_entry("DEBUG", "Not a TTY. Ctrl+P/Ctrl+R key listener disabled.")
             print("[Stdin] Not a TTY. Ctrl+P/Ctrl+R key listener disabled.")
        return # Explicitly exit if not a TTY

    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        write_log_entry("DEBUG", "Stdin key listener started.")
        while not stop_flag.is_set():
            if select.select([sys.stdin], [], [], 0.1)[0]:
                ch = sys.stdin.read(1)
                if ch:
                    c = ord(ch)
                    if c == 16:  # Ctrl+P
                        if pause_flag.is_set():
                            write_log_entry("INFO", "Ctrl+P detected. Pausing scan.")
                            print("\n[Ctrl+P] Pausing scan...", flush=True)
                            pause_flag.clear()
                        else:
                            print("\n[Ctrl+P] Already paused.", flush=True)
                    elif c == 18:  # Ctrl+R
                        if not pause_flag.is_set():
                            write_log_entry("INFO", "Ctrl+R detected. Resuming scan.")
                            print("\n[Ctrl+R] Resuming scan...", flush=True)
                            pause_flag.set()
                        else:
                            print("\n[Ctrl+R] Already running.", flush=True)
            else:
                time.sleep(0.05)
    except termios.error as e:
        write_log_entry("WARNING", "Failed to set TTY to cbreak for key listener.", error=str(e))
        if '--verbose' in sys.argv or '-v' in sys.argv:
            print(f"[Stdin] Failed to set TTY to cbreak: {e}. Ctrl+P/R may not work.")
    except Exception as e:
        write_log_entry("ERROR", "Exception in stdin_key_listener.", error=str(e))
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        write_log_entry("DEBUG", "Stdin key listener stopped.")

# =================== UTILITY FUNCTIONS ===================
def make_output_dirs(base_dir, target_identifier):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target_identifier = re.sub(r'[^\w\-_\.]', '_', target_identifier)
    dir_path = base_dir / f"{timestamp}_{safe_target_identifier}"
    dir_path.mkdir(parents=True, exist_ok=True)
    write_log_entry("DEBUG", "Created output directory.", path=str(dir_path))
    return dir_path

def is_locked(lock_file_path_base):
    return lock_file_path_base.with_suffix(LOCK_EXT).exists()

def create_lock(lock_file_path_base):
    lock_file = lock_file_path_base.with_suffix(LOCK_EXT)
    try:
        with open(lock_file, 'w') as f:
            f.write(f"Locked at {datetime.now()} by PID {os.getpid()}\n")
        write_log_entry("DEBUG", "Created lock file.", lock_file=str(lock_file))
    except IOError as e:
        write_log_entry("ERROR", "Failed to create lock file.", lock_file=str(lock_file), error=str(e))
        print(f"[Error] Failed to create lock file {lock_file}: {e}", file=sys.stderr)

def remove_lock(lock_file_path_base):
    lock_file = lock_file_path_base.with_suffix(LOCK_EXT)
    try:
        if lock_file.exists():
            lock_file.unlink()
            write_log_entry("DEBUG", "Removed lock file.", lock_file=str(lock_file))
    except OSError as e:
        write_log_entry("ERROR", "Failed to remove lock file.", lock_file=str(lock_file), error=str(e))
        print(f"[Error] Failed to remove lock file {lock_file}: {e}", file=sys.stderr)

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        write_log_entry("DEBUG", "DNS resolution failed (gaierror).", domain=domain, error=str(e))
        return None
    except Exception as e:
        write_log_entry("DEBUG", "DNS resolution failed (Exception).", domain=domain, error=str(e))
        return None

def timestamp_str():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

# =================== SCANNING FUNCTIONS ===================
def run_naabu(target, out_file_path, verbose=False):
    if stop_flag.is_set(): return False
    pause_flag.wait()

    cmd = ["naabu", "-host", target, "-p", ",".join(ALLOWED_PORTS),
           "-o", str(out_file_path), "-silent", "-stats", "-c", "50", "-rate", "1000",
           "-timeout", "1000", "-retries", str(MAX_RETRIES)]
    write_log_entry("INFO", "Starting Naabu scan.", target=target, command=" ".join(cmd))

    for attempt in range(MAX_RETRIES):
        if stop_flag.is_set(): return False
        pause_flag.wait()
        try:
            if verbose:
                print(f"[Naabu] Running attempt {attempt+1} for {target}: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)

            if process.returncode != 0:
                write_log_entry("WARNING", "Naabu process exited with non-zero code.", target=target, attempt=attempt+1, code=process.returncode, stderr=process.stderr.strip() if process.stderr else "N/A")
                if verbose: print(f"[Naabu] Warning: Naabu process for {target} exited with code {process.returncode}.")
                if process.stderr and verbose: print(f"[Naabu stderr]: {process.stderr.strip()}")

            if out_file_path.exists() and out_file_path.stat().st_size > 0:
                write_log_entry("INFO", "Naabu scan successful.", target=target, attempt=attempt+1, output_file=str(out_file_path))
                if verbose: print(f"[Naabu] Success for {target}, output at {out_file_path}")
                return True
            else:
                write_log_entry("WARNING", "Naabu output file empty or not created.", target=target, attempt=attempt+1, output_file=str(out_file_path))
                if verbose: print(f"[Naabu] Output file empty or not created for {target} on attempt {attempt+1}.")

        except subprocess.TimeoutExpired:
            write_log_entry("ERROR", "Naabu scan timed out.", target=target, attempt=attempt+1)
            if verbose: print(f"[Naabu] Timeout expired for {target} on attempt {attempt+1}.")
        except Exception as e:
            write_log_entry("ERROR", "Naabu scan exception.", target=target, attempt=attempt+1, error=str(e))
            if verbose: print(f"[Naabu] Exception on {target} attempt {attempt+1}: {e}")
        
        if attempt < MAX_RETRIES - 1:
            time.sleep(2 ** attempt)
    write_log_entry("ERROR", "Naabu scan failed after all retries.", target=target, attempts=MAX_RETRIES)
    return False

def curl_check(target_host_for_curl, port_to_check, injected_host_header, source_naabu_file, verbose=False):
    scheme = "http"
    url = f"{scheme}://{target_host_for_curl}:{port_to_check}"

    cmd = [
        "curl", "-s",
        "-o", "/dev/null",
        "-D", "-",
        "-H", f"Host: {injected_host_header}",
        "--max-time", "10",
        "--connect-timeout", "5",
        "--path-as-is",
        "-L",
        "--insecure",
        url
    ]
    log_extra = {"url": url, "injected_host": injected_host_header, "target_for_curl": target_host_for_curl, "port": port_to_check}

    for attempt in range(MAX_RETRIES):
        if stop_flag.is_set(): return None
        pause_flag.wait()
        try:
            if verbose:
                print(f"[Curl] Attempt {attempt+1} for {injected_host_header} -> {url} (via {target_host_for_curl}:{port_to_check})")
            
            write_log_entry("DEBUG", "Starting Curl check.", attempt=attempt+1, **log_extra)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout

            if verbose:
                last_headers = output.strip().split("\r\n\r\n")[-1] if output.strip() else ""
                print(f"[Curl Output for {url} with Host: {injected_host_header}]\n{last_headers}\n--------------------")

            final_status_code, final_location = None, None
            header_blocks = [block for block in output.strip().split("\r\n\r\n") if block.strip()]
            
            if header_blocks:
                last_block = header_blocks[-1]
                status_match = re.search(r"^HTTP/(?:1\.1|2|3)\s+(\d{3})", last_block, re.MULTILINE)
                if status_match: final_status_code = status_match.group(1)
                location_match = re.search(r"^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:\s*(.+)$", last_block, re.MULTILINE)
                if location_match: final_location = location_match.group(1).strip()
            
            write_log_entry("DEBUG", "Curl check completed.", status_code=final_status_code, location=final_location, **log_extra)
            
            if final_status_code:
                return {
                    "domain_tested": injected_host_header,
                    "target_ip_port": f"{target_host_for_curl}:{port_to_check}",
                    "naabu_source_file": str(source_naabu_file),
                    "status_code": final_status_code,
                    "location": final_location,
                    "full_headers": output.strip()
                }

        except subprocess.TimeoutExpired:
            write_log_entry("WARNING", "Curl check timed out.", attempt=attempt+1, **log_extra)
            if verbose: print(f"[Curl] Timeout for {url} (Host: {injected_host_header}) attempt {attempt+1}")
        except Exception as e:
            write_log_entry("ERROR", "Curl check exception.", attempt=attempt+1, error=str(e), **log_extra)
            if verbose: print(f"[Curl] Exception for {url} (Host: {injected_host_header}) attempt {attempt+1}: {e}")
        
        if attempt < MAX_RETRIES - 1:
            time.sleep(1)
    write_log_entry("ERROR", "Curl check failed after all retries.", **log_extra)
    return None

def save_target_run_results(target_run_output_dir, input_target_domain, results_for_target, tested_host_header, verbose=False):
    csv_file = target_run_output_dir / "scan_run_details.csv"
    txt_file = target_run_output_dir / "scan_run_details.txt"
    
    write_log_entry("INFO", "Attempting to save target run results.", directory=str(target_run_output_dir), count=len(results_for_target) if results_for_target else 0)

    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as cf, \
             open(txt_file, 'w', encoding='utf-8') as tf:
            
            csv_writer = csv.writer(cf)
            csv_writer.writerow(["Input Target", "Host Header Tested", "Target IP:Port Found by Naabu", "Final Status Code", "Final Redirect Location", "Naabu Output File"])

            tf.write(f"🔍 Scan Results for Input Target: {input_target_domain}\n")
            tf.write(f"   (Tested with Host Header: {tested_host_header})\n")
            tf.write("="*50 + "\n")

            if results_for_target:
                for res in results_for_target:
                    is_redirect = res.get("status_code", "").startswith("3") and res.get("location")
                    got_any_status = res.get("status_code") is not None
                    status_icon = "✅" if is_redirect else ("➡️" if got_any_status else "❌")
                    
                    csv_writer.writerow([
                        input_target_domain,
                        res["domain_tested"],
                        res["target_ip_port"],
                        res["status_code"],
                        res.get("location", "-"),
                        res["naabu_source_file"]
                    ])
                    tf.write(f"{status_icon} {res['domain_tested']} on {res['target_ip_port']} -> Status: {res['status_code']}, Location: {res.get('location', 'N/A')}\n")
            else:
                tf.write("❌ No HTTP responses captured from Curl checks, or all checks failed.\n")
        
        write_log_entry("INFO", "Target run results successfully saved.", directory=str(target_run_output_dir))
        if verbose:
            print(f"[Save] Saved target run results to {target_run_output_dir}")
    except Exception as e:
        write_log_entry("ERROR", "Failed to save target run results.", directory=str(target_run_output_dir), error=str(e), traceback=traceback.format_exc())
        print(f"[Error] Failed to save target run results for {input_target_domain}: {e}", file=sys.stderr)


def update_run_summary(run_timestamp, all_results_from_current_run, verbose=False):
    write_log_entry("INFO", "Attempting to generate run-specific summary.", timestamp=run_timestamp)
    if not all_results_from_current_run:
        write_log_entry("INFO", "No results from this run to generate a run summary. Skipping.")
        if verbose: print("[Summary] No results from this run to summarize.")
        return

    csv_summary_file = RUN_SUMMARY_DIR / f"run_summary_{run_timestamp}.csv"
    txt_summary_file = RUN_SUMMARY_DIR / f"run_summary_{run_timestamp}.txt"
    html_summary_file = RUN_SUMMARY_DIR / f"run_summary_{run_timestamp}.html"

    sorted_results = sorted(all_results_from_current_run, key=lambda x: (x["domain_tested"], x["target_ip_port"]))

    try:
        write_log_entry("DEBUG", "Writing run summary CSV.", file=str(csv_summary_file))
        with open(csv_summary_file, 'w', newline='', encoding='utf-8') as cf:
            csv_writer = csv.writer(cf)
            csv_writer.writerow(["Host Header Tested", "Target IP:Port", "Status Code", "Redirect Location"])
            for r in sorted_results:
                csv_writer.writerow([r["domain_tested"], r["target_ip_port"], r["status_code"], r.get("location", "-")])
        write_log_entry("DEBUG", "Run summary CSV written.", file=str(csv_summary_file))

        write_log_entry("DEBUG", "Writing run summary TXT.", file=str(txt_summary_file))
        with open(txt_summary_file, 'w', encoding='utf-8') as tf:
            tf.write(f"🔍 Scan Summary for Run: {run_timestamp}\n")
            tf.write("="*40 + "\n")
            for r in sorted_results:
                is_redirect = r.get("status_code", "").startswith("3") and r.get("location")
                status_icon = "✅" if is_redirect else "➡️"
                tf.write(f"{status_icon} {r['domain_tested']} on {r['target_ip_port']} -> Status: {r['status_code']}, Location: {r.get('location', 'N/A')}\n")
        write_log_entry("DEBUG", "Run summary TXT written.", file=str(txt_summary_file))

        total_entries = len(sorted_results)
        total_redirects_in_run = sum(1 for r in sorted_results if r.get("status_code", "").startswith("3") and r.get("location"))
        total_non_redirect_responses = sum(1 for r in sorted_results if not (r.get("status_code", "").startswith("3") and r.get("location")) and r.get("status_code") is not None)

        html_content = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Run Scan Summary ({run_timestamp})</title>
        <style>body{{font-family:Arial,sans-serif;margin:20px;background-color:#f8f9fa;}}h1{{color:#333;text-align:center}}
        .stats{{background-color:#e9ecef;padding:15px;border-radius:5px;margin-bottom:20px;text-align:center}}
        table{{width:90%;margin:20px auto;border-collapse:collapse;box-shadow:0 0 10px rgba(0,0,0,0.1);}}
        th,td{{border:1px solid #dee2e6;padding:10px;text-align:left;}}th{{background-color:#007bff;color:white;}}
        tr:nth-child(even){{background-color:#f2f2f2;}} .status-redirect{{color:green;font-weight:bold;}}
        .status-no-redirect{{color:darkorange;}} .status-failed{{color:red;}}
        footer{{text-align:center;margin-top:20px;font-size:0.9em;color:#6c757d;}}
        </style></head><body><h1>📈 Run Scan Summary ({run_timestamp})</h1>
        <div class="stats">
          <p><strong>Total HTTP responses captured in this run:</strong> {total_entries}</p>
          <p><strong>Redirects (3xx with Location):</strong> {total_redirects_in_run}</p>
          <p><strong>Other HTTP responses:</strong> {total_non_redirect_responses}</p>
        </div>
        <table><thead><tr><th>Host Header Tested</th><th>Target IP:Port</th><th>Status Code</th><th>Redirect Location</th></tr></thead><tbody>
        """
        for r in sorted_results:
            is_redirect = r.get("status_code", "").startswith("3") and r.get("location")
            status_class = "status-redirect" if is_redirect else "status-no-redirect"
            html_content += f"""<tr>
            <td>{escape(r['domain_tested'])}</td><td>{escape(r['target_ip_port'])}</td>
            <td class="{status_class}">{escape(str(r['status_code']))}</td>
            <td>{escape(r.get('location', '-'))}</td></tr>"""
        html_content += f"</tbody></table><footer>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer></body></html>"
        
        write_log_entry("DEBUG", "Writing run summary HTML.", file=str(html_summary_file))
        with open(html_summary_file, 'w', encoding='utf-8') as hf:
            hf.write(html_content)
        write_log_entry("DEBUG", "Run summary HTML written.", file=str(html_summary_file))

        write_log_entry("INFO", "Run-specific summary successfully generated.", timestamp=run_timestamp, result_count=len(all_results_from_current_run))
        if verbose:
            print(f"[Summary] Saved run summary for {run_timestamp} to {RUN_SUMMARY_DIR}")
    except Exception as e:
        write_log_entry("ERROR", "Failed to generate run-specific summary.", timestamp=run_timestamp, error=str(e), traceback=traceback.format_exc())
        print(f"[Error] Failed to generate run-specific summary: {e}", file=sys.stderr)


def update_master_summary(all_results_from_current_run, verbose=False):
    master_csv_file = MASTER_SUMMARY_DIR / "master_summary.csv"
    master_html_file = MASTER_SUMMARY_DIR / "master_summary.html"
    write_log_entry("INFO", "Attempting to update master summary.")

    existing_master_entries = []
    seen_keys = set()

    if master_csv_file.exists():
        try:
            write_log_entry("DEBUG", "Loading existing master summary CSV.", file=str(master_csv_file))
            with open(master_csv_file, 'r', newline='', encoding='utf-8') as cf:
                reader = csv.DictReader(cf)
                for row in reader:
                    existing_master_entries.append(row)
                    key = (row["Host Header Tested"], row["Target IP:Port"])
                    seen_keys.add(key)
            write_log_entry("DEBUG", "Loaded existing master summary CSV.", count=len(existing_master_entries))
        except Exception as e:
            write_log_entry("ERROR", "Could not read existing master CSV. Starting fresh master summary.", file=str(master_csv_file), error=str(e), traceback=traceback.format_exc())
            print(f"[Warning] Could not read existing master CSV. Starting fresh master summary: {e}", file=sys.stderr)
            existing_master_entries = []
            seen_keys = set()

    new_redirects_for_master = []
    updated_count = 0

    if all_results_from_current_run:
        for res in all_results_from_current_run:
            is_redirect_for_master = res.get("status_code", "").startswith("3") and res.get("location")
            if not is_redirect_for_master:
                continue

            key = (res["domain_tested"], res["target_ip_port"])
            if key not in seen_keys:
                new_master_entry = {
                    "Host Header Tested": res["domain_tested"],
                    "Target IP:Port": res["target_ip_port"],
                    "Status Code": res["status_code"],
                    "Redirect Location": res.get("location", "-"),
                    "First Seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Last Seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                new_redirects_for_master.append(new_master_entry)
                seen_keys.add(key)
            else:
                updated_existing = False
                for existing_entry in existing_master_entries:
                    if (existing_entry["Host Header Tested"], existing_entry["Target IP:Port"]) == key:
                        existing_entry["Last Seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        existing_entry["Status Code"] = res["status_code"]
                        existing_entry["Redirect Location"] = res.get("location", "-")
                        updated_existing = True
                        updated_count +=1
                        break
                if not updated_existing and verbose:
                    write_log_entry("WARNING", "Logic error: Key in seen_keys but not found in existing_master_entries for update.", key=str(key))
    write_log_entry("INFO", "Master summary processing completed for current run results.", new_redirects=len(new_redirects_for_master), updated_entries=updated_count)

    if not new_redirects_for_master and not existing_master_entries:
        if verbose: print("[Master Summary] No new or existing redirect results to create/update master summary.")
        write_log_entry("INFO", "No new or existing redirect results to create/update master summary. Skipping master summary generation.")
        return

    combined_master_data = existing_master_entries + new_redirects_for_master
    combined_master_data.sort(key=lambda x: (x["Host Header Tested"], x["Target IP:Port"]))
    fieldnames = ["Host Header Tested", "Target IP:Port", "Status Code", "Redirect Location", "First Seen", "Last Seen"]
    
    try:
        write_log_entry("DEBUG", "Writing master summary CSV.", file=str(master_csv_file))
        with open(master_csv_file, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(combined_master_data)
        write_log_entry("DEBUG", "Master summary CSV written.", file=str(master_csv_file))

        total_master_entries = len(combined_master_data)

        sort_filter_script = """
        <script>
        function sortTable(n, tableId) {
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById(tableId);
            switching = true;
            dir = "asc";
            while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir == "desc") {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc";
                        switching = true;
                    }
                }
            }
        }

        function filterTable(inputId, tableId) {
            var input, filter, table, tr, td, i, j, txtValue;
            input = document.getElementById(inputId);
            filter = input.value.toUpperCase();
            table = document.getElementById(tableId);
            tr = table.getElementsByTagName("tr");
            for (i = 1; i < tr.length; i++) {
                tr[i].style.display = "none";
                for (j = 0; j < tr[i].getElementsByTagName("td").length; j++) {
                    td = tr[i].getElementsByTagName("td")[j];
                    if (td) {
                        txtValue = td.textContent || td.innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            tr[i].style.display = "";
                            break;
                        }
                    }
                }
            }
        }
        </script>
        """
        html_content = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Master Scan Summary (Redirects)</title>
        <style>
        body{{font-family:Verdana,sans-serif;margin:20px;background-color:#f0f2f5;}}
        h1{{color:#2c3e50;text-align:center;}}
        .stats{{background-color:#e3f2fd;padding:15px;border-radius:8px;margin-bottom:20px;text-align:center;border:1px solid #bbdefb;}}
        #filterInput{{width:90%;padding:10px;margin:10px auto;display:block;border:1px solid #ccc;border-radius:4px;}}
        table{{width:95%;margin:20px auto;border-collapse:collapse;box-shadow:0 2px 15px rgba(0,0,0,0.1);background-color:white;}}
        th,td{{border:1px solid #ddd;padding:12px;text-align:left;}}
        th{{background-color:#3498db;color:white;cursor:pointer;user-select:none;}}
        th:hover{{background-color:#2980b9;}}
        tr:nth-child(even){{background-color:#ecf0f1;}}
        tr:hover{{background-color:#d6eaf8;}}
        .status-redirect{{color:#27ae60;font-weight:bold;}}
        .status-no-redirect{{color:#e67e22;}}
        .status-failed{{color:#c0392b;}}
        footer{{text-align:center;margin-top:20px;font-size:0.8em;color:#7f8c8d;}}
        </style>
        </head>
        <body>
        <h1>📊 Master Scan Summary (Redirects)</h1>
        <div class="stats">
          <p><strong>Total Unique Redirects Found:</strong> {total_master_entries}</p>
        </div>
        <input type="text" id="filterInput" onkeyup="filterTable('filterInput', 'masterSummaryTable')" placeholder="Filter by host, IP:Port, status, or location...">
        <table id="masterSummaryTable">
          <thead>
            <tr>
              <th onclick="sortTable(0, 'masterSummaryTable')">Host Header Tested</th>
              <th onclick="sortTable(1, 'masterSummaryTable')">Target IP:Port</th>
              <th onclick="sortTable(2, 'masterSummaryTable')">Status Code</th>
              <th onclick="sortTable(3, 'masterSummaryTable')">Redirect Location</th>
              <th onclick="sortTable(4, 'masterSummaryTable')">First Seen</th>
              <th onclick="sortTable(5, 'masterSummaryTable')">Last Seen</th>
            </tr>
          </thead>
          <tbody>
        """
        for row in combined_master_data:
            is_redirect = str(row.get("Status Code", "")).startswith("3") and row.get("Redirect Location")
            status_class = "status-redirect" if is_redirect else "status-no-redirect"
            html_content += f"""
            <tr>
                <td>{escape(row['Host Header Tested'])}</td>
                <td>{escape(row['Target IP:Port'])}</td>
                <td class="{status_class}">{escape(str(row['Status Code']))}</td>
                <td>{escape(row.get('Redirect Location', '-'))}</td>
                <td>{escape(row.get('First Seen', 'N/A'))}</td>
                <td>{escape(row.get('Last Seen', 'N/A'))}</td>
            </tr>
            """
        html_content += f"""
          </tbody>
        </table>
        <footer>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
        {sort_filter_script}
        </body></html>
        """
        write_log_entry("DEBUG", "Writing master summary HTML.", file=str(master_html_file))
        with open(master_html_file, 'w', encoding='utf-8') as hf:
            hf.write(html_content)
        write_log_entry("DEBUG", "Master summary HTML written.", file=str(master_html_file))

        write_log_entry("INFO", "Master summary successfully updated.", total_entries=total_master_entries)
        if verbose:
            print(f"[Summary] Updated master summary at {MASTER_SUMMARY_DIR}")
    except Exception as e:
        write_log_entry("ERROR", "Failed to update master summary.", error=str(e), traceback=traceback.format_exc())
        print(f"[Error] Failed to update master summary: {e}", file=sys.stderr)


# =================== CORE SCAN LOGIC ===================
class ScanManager:
    def __init__(self, targets_to_scan, max_workers, verbose, host_header_override=None):
        self.initial_targets = targets_to_scan
        self.max_workers = max_workers
        self.verbose = verbose
        self.host_header_override = host_header_override

        self.scan_state_file = STATE_DIR / f"{STATE_FILENAME_PREFIX}.json"
        self.state_file_path = self.scan_state_file
        
        self.scan_state = self.load_state()
        self.all_results_current_run = []

        if not self.scan_state.get("pending_targets"):
            write_log_entry("INFO", "No pending targets found in state. Initializing from provided targets.", initial_target_count=len(self.initial_targets))
            self.scan_state["pending_targets"] = list(self.initial_targets)
            self.scan_state["scanned_targets_status"] = {}

        self.scan_state["pending_targets"] = [t for t in self.scan_state["pending_targets"] if t is not None]


    def load_state(self):
        write_log_entry("INFO", "Attempting to load scan state.")
        if self.state_file_path.exists():
            try:
                with open(self.state_file_path, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                write_log_entry("INFO", "Loaded previous scan state.", file=str(self.state_file_path))

                if "scanned_targets_status" not in state: state["scanned_targets_status"] = {}
                if "pending_targets" not in state: state["pending_targets"] = []

                state["pending_targets"] = [t for t in state["pending_targets"] if t is not None]
                return state
            except json.JSONDecodeError as e:
                write_log_entry("ERROR", "State file corrupted. Initializing new state.", file=str(self.state_file_path), error=str(e), traceback=traceback.format_exc())
                print(f"[Warning] State file {self.state_file_path} is corrupted. Initializing new state.", file=sys.stderr)
            except Exception as e:
                 write_log_entry("ERROR", "Could not load state file. Initializing new state.", file=str(self.state_file_path), error=str(e), traceback=traceback.format_exc())
                 print(f"[Warning] Could not load state file {self.state_file_path}: {e}. Initializing new state.", file=sys.stderr)
        write_log_entry("INFO", "No previous state file found or loaded. Initializing new state.")
        return {"scanned_targets_status": {}, "pending_targets": [t for t in list(self.initial_targets) if t is not None]}


    def save_state(self):
        # Optional: You can keep this log if you want, but it's not strictly necessary,
        # as the 'with' block below implicitly means an attempt to acquire the lock.
        # write_log_entry("DEBUG", "Attempting to acquire general_file_lock in save_state.")

        # >>> CRITICAL CHANGE: This line is now UNCOMMENTED <<<
        with general_file_lock:

            # >>> THESE MISLEADING LOG LINES HAVE BEEN REMOVED/COMMENTED OUT <<<
            # write_log_entry("DEBUG", "Acquired general_file_lock in save_state. (Lock removed for testing purposes)")
            # write_log_entry("INFO", "Attempting to save scan state.") # You can uncomment and keep this one if you like

            # All the code below this is correctly indented to be inside the 'with general_file_lock:' block.

            if self.state_file_path.exists():
                try:
                    write_log_entry("DEBUG", "Attempting to create state file backup.")
                    backups = sorted(STATE_DIR.glob(f"{STATE_FILENAME_PREFIX}_backup_*.json"))
                    if len(backups) >= MAX_BACKUPS:
                        backups[0].unlink()
                    backup_path = STATE_DIR / f"{STATE_FILENAME_PREFIX}_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
                    shutil.copy(self.state_file_path, backup_path)
                    write_log_entry("DEBUG", "Created state file backup.", from_path=str(self.state_file_path), to_path=str(backup_path))
                except Exception as e:
                    write_log_entry("WARNING", "Failed to create state file backup.", error=str(e), traceback=traceback.format_exc())
                    print(f"[Warning] Failed to create state file backup: {e}", file=sys.stderr)

            try:
                write_log_entry("DEBUG", "Preparing pending targets for state save.")
                current_pending = [t for t, status in self.scan_state["scanned_targets_status"].items() if status == "pending"]
                initial_targets_set = set(self.initial_targets)
                scanned_targets_set = set(self.scan_state["scanned_targets_status"].keys())
                unprocessed_initial = [t for t in self.initial_targets if t not in scanned_targets_set]

                self.scan_state["pending_targets"] = list(set(current_pending + unprocessed_initial))

                self.scan_state["pending_targets"] = [t for t in self.scan_state["pending_targets"] if t is not None]

                write_log_entry("DEBUG", "Attempting to dump JSON state to file.")
                with open(self.state_file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_state, f, indent=4)
                write_log_entry("INFO", "Scan state saved successfully.", path=str(self.state_file_path), pending_count=len(self.scan_state["pending_targets"]))
                if self.verbose:
                    print(f"\n[State] Scan state saved to {self.state_file_path} ({len(self.scan_state['pending_targets'])} targets pending).")
            except Exception as e:
                write_log_entry("ERROR", "Failed to save scan state.", error=str(e), traceback=traceback.format_exc())
                print(f"[Error] Failed to save scan state: {e}", file=sys.stderr)

            # >>> THIS MISLEADING LOG LINE HAS BEEN REMOVED/COMMENTED OUT <<<
            # write_log_entry("DEBUG", "Released general_file_lock in save_state. (Lock removed for testing purposes)")


    def process_single_target(self, input_target_domain):
        if stop_flag.is_set(): return []
        pause_flag.wait()

        if input_target_domain is None:
            write_log_entry("ERROR", "process_single_target received None as input_target_domain. Skipping.", target=input_target_domain)
            return []

        naabu_lock_base_name = input_target_domain.replace(":", "_").replace("/", "_")
        naabu_lock_path_base = NAABU_LOCK_DIR / naabu_lock_base_name

        if is_locked(naabu_lock_path_base):
            write_log_entry("INFO", "Target is locked, skipping for this run.", target=input_target_domain, lock_file=str(naabu_lock_path_base.with_suffix(LOCK_EXT)))
            if self.verbose:
                print(f"[Skip] Target {input_target_domain} is locked, skipping.")
            with general_file_lock:
                self.scan_state["scanned_targets_status"][input_target_domain] = "skipped"
            return []

        create_lock(naabu_lock_path_base)
        
        naabu_output_dir = make_output_dirs(INJECT_DIR, input_target_domain)
        naabu_output_file = naabu_output_dir / "naabu_output.txt"
        
        target_curl_results = []
        host_header_to_use = self.host_header_override if self.host_header_override else input_target_domain

        try:
            if not run_naabu(input_target_domain, naabu_output_file, verbose=self.verbose):
                write_log_entry("WARNING", "Naabu scan failed for target.", target=input_target_domain)
                with general_file_lock:
                    self.scan_state["scanned_targets_status"][input_target_domain] = "naabu_failed"
                return []

            naabu_ips = []
            if naabu_output_file.exists():
                with open(naabu_output_file, 'r', encoding='utf-8') as f:
                    naabu_ips = [line.strip() for line in f if line.strip()]

            if not naabu_ips:
                write_log_entry("INFO", "Naabu found no open ports for target.", target=input_target_domain)
                if self.verbose: print(f"[Naabu] No open ports found for {input_target_domain}")
                with general_file_lock:
                    self.scan_state["scanned_targets_status"][input_target_domain] = "no_open_ports"
                return []

            write_log_entry("INFO", "Naabu found open ports.", target=input_target_domain, ports_found=len(naabu_ips))
            if self.verbose: print(f"[Naabu] Found {len(naabu_ips)} open ports for {input_target_domain}. Proceeding with Curl checks...")

            for ip_port in naabu_ips:
                if stop_flag.is_set(): break
                pause_flag.wait()

                parts = ip_port.split(":")
                target_ip = parts[0]
                port = parts[1] if len(parts) > 1 else "80"

                if port not in ALLOWED_PORTS:
                    write_log_entry("INFO", "Skipping port not in ALLOWED_PORTS.", target=input_target_domain, ip_port=ip_port, port=port)
                    continue

                curl_result = curl_check(target_ip, port, host_header_to_use, naabu_output_file, verbose=self.verbose)
                if curl_result:
                    target_curl_results.append(curl_result)

            with general_file_lock:
                self.scan_state["scanned_targets_status"][input_target_domain] = "completed"
                if target_curl_results:
                    if any(res.get("status_code", "").startswith("3") and res.get("location") for res in target_curl_results):
                        self.scan_state["scanned_targets_status"][input_target_domain] = "vulnerable"
                    else:
                        self.scan_state["scanned_targets_status"][input_target_domain] = "completed_no_redirect"
                else:
                    self.scan_state["scanned_targets_status"][input_target_domain] = "completed_no_http_response"

            if target_curl_results:
                save_target_run_results(naabu_output_dir, input_target_domain, target_curl_results, host_header_to_use, verbose=self.verbose)

            return target_curl_results

        except Exception as e:
            write_log_entry("ERROR", "Error during process_single_target.", target=input_target_domain, error=str(e), traceback=traceback.format_exc())
            print(f"[Error] Exception in process_single_target for {input_target_domain}: {e}", file=sys.stderr)
            with general_file_lock:
                self.scan_state["scanned_targets_status"][input_target_domain] = "error"
            return []

        finally:
            remove_lock(naabu_lock_path_base)


    def run_scan(self):
        run_timestamp = datetime.now().isoformat()
        write_log_entry("INFO", "Scan started.", start_time=run_timestamp)
        print(f"[*] Scan started at: {run_timestamp}")

        if self.host_header_override:
            write_log_entry("INFO", "Host Header for curl checks overridden.", host_header=self.host_header_override)
            print(f"[*] Host Header for curl checks: {self.host_header_override}")
        else:
            write_log_entry("INFO", "Host Header for curl checks derived from target.", host_header="dynamic")
            print(f"[*] Host Header for curl checks: {HOST_HEADER} (default, or derived from target)")


        targets_to_process_this_run = [
            t for t in self.scan_state["pending_targets"]
            if self.scan_state["scanned_targets_status"].get(t) not in ["completed", "vulnerable", "skipped", "naabu_failed", "no_open_ports", "completed_no_http_response", "completed_no_redirect"]
        ]
        
        if not targets_to_process_this_run and self.initial_targets:
            write_log_entry("INFO", "No pending targets after status filter. Re-initializing with all initial targets for new run.", initial_target_count=len(self.initial_targets))
            targets_to_process_this_run = list(self.initial_targets)
            self.scan_state["scanned_targets_status"] = {}

        for t in targets_to_process_this_run:
            self.scan_state["scanned_targets_status"][t] = "pending"
        
        write_log_entry("INFO", "Number of targets to process in this run.", count=len(targets_to_process_this_run))
        print(f"[*] Number of targets to process in this run: {len(targets_to_process_this_run)}")

        stdin_thread = threading.Thread(target=stdin_key_listener, daemon=True)
        stdin_thread.start()

        def state_saver_thread_func(): # Renamed to avoid confusion with class method
            while not stop_flag.is_set():
                time.sleep(SAVE_INTERVAL)
                if not stop_flag.is_set():
                    self.save_state()
        saver_thread = threading.Thread(target=state_saver_thread_func, daemon=True) # Use new name
        saver_thread.start()

        pause_flag.set()

        submitted_count = 0
        with tqdm(total=len(targets_to_process_this_run), desc="Submitting tasks", unit="target", disable=not self.verbose) as pbar_submit:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.process_single_target, input_target_domain): input_target_domain for input_target_domain in targets_to_process_this_run}
                submitted_count = len(futures)
                pbar_submit.update(submitted_count)

                write_log_entry("INFO", "All tasks submitted. Waiting for completion...", submitted_count=submitted_count)
                print(f"[*] All {submitted_count} tasks submitted. Waiting for completion...")

                pbar_process = tqdm(total=submitted_count, desc="Processing targets", unit="target")
                for future in as_completed(futures):
                    target = futures[future]
                    pbar_process.update(1)
                    try:
                        result_data = future.result()
                        if result_data:
                            self.all_results_current_run.extend(result_data)
                    except Exception as e:
                        write_log_entry("ERROR", "Error processing target in thread pool.", target=target, error=str(e), traceback=traceback.format_exc())
                        if self.verbose:
                            print(f"[Error] Worker for {target} failed: {e}", file=sys.stderr)
                        with general_file_lock:
                            self.scan_state["scanned_targets_status"][target] = "worker_error"
                pbar_process.close()

        self._finalize_run(run_timestamp)

    def _finalize_run(self, run_timestamp):
        write_log_entry("INFO", "Finalizing scan run initiated.")
        print("\n[*] Finalizing scan run...", flush=True)
        
        write_log_entry("INFO", "Attempting to save final state before summaries.")
        self.save_state()
        write_log_entry("INFO", "Final state saved.")

        print("\n[*] Generating run-specific summaries (CSV, TXT, HTML)... This might take a moment.", flush=True)
        write_log_entry("INFO", "Updating run-specific summary (includes all HTTP responses)...")
        update_run_summary(run_timestamp, self.all_results_current_run, verbose=self.verbose)
        write_log_entry("INFO", "Run-specific summary update attempt finished.")
        print("[*] Run-specific summaries generated.", flush=True)

        print("[*] Updating master summary (CSV, HTML)... This might also take a moment.", flush=True)
        write_log_entry("INFO", "Updating master summary.")
        update_master_summary(self.all_results_current_run, verbose=self.verbose)
        write_log_entry("INFO", "Master summary update attempt finished.")
        print("[*] Master summary updated.", flush=True)
        
        write_log_entry("INFO", "Scan completed.", end_time=datetime.now().isoformat())
        print(f"[*] Scan completed at: {datetime.now().isoformat()}")

        status_counts = {}
        for status in self.scan_state["scanned_targets_status"].values():
            status_counts[status] = status_counts.get(status, 0) + 1
        
        print("\n--- Scan Summary Status ---")
        for status, count in status_counts.items():
            print(f"  - {status.replace('_', ' ').title()}: {count} targets")
        print("---------------------------\n")

def load_targets_from_file(file_path):
    if not Path(file_path).exists():
        write_log_entry("ERROR", "Target list file not found.", path=file_path)
        raise FileNotFoundError(f"Target list file not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    write_log_entry("INFO", "Loaded targets from file.", path=file_path, count=len(targets))
    return targets

def main():
    parser = argparse.ArgumentParser(description="Host Header Injection Scan Tool")
    parser.add_argument("-l", "--list", required=True, help="Path to the list of target domains/IPs.")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent workers (threads).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-H", "--host-header", type=str, default=HOST_HEADER,
                        help=f"Override the Host header injected into curl requests. Default: {HOST_HEADER}")
    parser.add_argument("--clear-state", action="store_true", help="Clear previous scan state before starting.")

    args = parser.parse_args()

    if args.clear_state:
        state_file = STATE_DIR / f"{STATE_FILENAME_PREFIX}.json"
        if state_file.exists():
            state_file.unlink()
            write_log_entry("INFO", "Previous scan state cleared by user.", path=str(state_file))
            print(f"[*] Cleared previous scan state: {state_file}")
        else:
            print("[*] No previous scan state file found to clear.")

    targets_from_file = load_targets_from_file(args.list)

    if not targets_from_file:
        write_log_entry("WARNING", "No targets found in list file.", path=args.list)
        sys.exit(0)

    print(f"[*] Initializing ScanManager with {len(targets_from_file)} targets from '{args.list}'.")
    print(f"[*] Max workers: {args.workers}, Allowed ports for Curl: {ALLOWED_PORTS}")
    if args.verbose:
        print("[*] Verbose mode enabled.")

    manager = ScanManager(
        targets_to_scan=targets_from_file,
        max_workers=args.workers,
        verbose=args.verbose,
        host_header_override=args.host_header
    )
    manager.run_scan()
    write_log_entry("INFO", "Script execution finished.", end_time=datetime.now().isoformat())

if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code != 0:
             write_log_entry("CRITICAL", "Script exited with error code.", exit_code=e.code)
        sys.exit(e.code)
    except KeyboardInterrupt:
        write_log_entry("CRITICAL", "Script interrupted by KeyboardInterrupt (main).")
        print("\n[!] Main KeyboardInterrupt. Exiting.")
        stop_flag.set()
        sys.exit(1)
    except Exception as e:
        error_message = f"Unhandled critical error: {e}"
        write_log_entry("CRITICAL", error_message, error=str(e), traceback=traceback.format_exc())
        print(f"\n[!!!] {error_message}. Check logs for details.")
        print(traceback.format_exc(), file=sys.stderr)
        sys.exit(1)
