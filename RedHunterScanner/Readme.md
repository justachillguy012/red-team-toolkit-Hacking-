# RedHunterScanner

A simple multi-threaded web vulnerability scanner with a Tkinter-based UI.  
Detects:
- **SQL Injection** (basic payloads + heuristics)
- **XSS** (reflected payload check)
- **Local File Inclusion (LFI)** (path traversal payloads + checks)
- **Directory Discovery** (basic wordlist scanning)

---

## Features
- Easy-to-use **Graphical Interface**.
- Multi-threaded for faster scanning.
- Works on Windows, macOS, and Linux (Python version).
- **Portable `.exe` version** available for Windows (no Python required).

---

## Installation (Python Script Version)
1. **Clone the repository:**
   ```bash
   git clone https://github.com/justachillguy012/red-team-toolkit-Hacking-.git
   cd red-team-toolkit-Hacking-/RedHunterScanner
   pip install -r requirements.txt
   python RedHunterScanner.py
