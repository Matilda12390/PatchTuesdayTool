# 🛠️ Patch Tuesday CVE Report Tool

This tool gathers CVE (Common Vulnerabilities and Exposures) information from **Microsoft**, **Adobe**, and **SAP**, checks exposure status on **Feedly**, and exports a spreadsheet of vulnerabilities for a selected month.

No technical knowledge needed — just follow the simple steps below.

---

## **Requirements**
- Windows 10/11 (no Python required for Option 4)
- Internet connection (for fetching advisories and enrichment data)

---

## **Options to Run**

### **Option 1 — Average**
1. Download and install the latest **Python for Windows** from:
   - [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
   - Tick **"Add Python to PATH"** during install.

2. Download this repository as ZIP and extract it.

3. Open Command Prompt in the extracted folder:
   ```sh
   pip install -r requirements.txt
   python PatchTuesday.py --microsoft
   ```

---

### **Option 2 — With WSL**

1. Install **Windows Subsystem for Linux (WSL)** if not already installed:

   ```powershell
   wsl --install
   ```

   *(You may need to reboot)*

2. From your WSL terminal:

   ```sh
   sudo apt update && sudo apt install python3-pip -y
   pip3 install -r requirements.txt
   python3 PatchTuesday.py --microsoft
   ```

---

### **Option 3 — Manual Python Install Without PATH**

1. Download the **Embeddable Python ZIP** from:

   * [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
     *(Look for "Windows embeddable package" for your architecture — e.g., `amd64`)*

2. Extract to a folder, e.g. `C:\PythonPortable`.

3. From Command Prompt in your project folder:

   ```sh
   C:\PythonPortable\python.exe -m pip install -r requirements.txt
   C:\PythonPortable\python.exe PatchTuesday.py --microsoft
   ```

---

### **Option 4 — Ultra-Lazy: Just Unzip & Run (No Setup Needed)**

If you don't want to install anything, we provide a ready-to-use package.

**1. Download the Pre-Packaged ZIP**

* [📦 Download ZIP from GitHub Releases](https://github.com/Matilda12390/PatchTuesdayTool/releases/tag/Release) *(look for `PatchTuesday.zip`)*

**2. Extract It Anywhere**

* For example: `C:\MyTools\Project\`

**3. Run the Script**

* Double-click `run.bat`
* The script will open a console window and start running immediately.
* Follow the prompts

---

#### **What's Inside the ZIP**

* **Portable Python** — runs without installing to Windows
* **All Dependencies** — already installed, no `pip` needed
* **Your Script** — ready to execute
* **`run.bat`** — one-click launcher

---

#### **Troubleshooting**

* If Windows SmartScreen blocks the `.bat` file, click **More info → Run anyway**.
* No admin rights are required.
* Works entirely offline after download (except when the script itself fetches data).


## 📦 What's Included
```
PatchTuesdayTool/
├── PatchTuesday.py ← Main script
├── requirements.txt ← Python dependencies
├── README.md ← You are here
```

## ▶️ How to Use

⚙️ Available Options
| Option        | Description                                           |
| ------------- | ----------------------------------------------------- |
| `--month`     | **(Required)** The month to check, format: `Jul-2025` |
| `--microsoft` | Include Microsoft Patch Tuesday CVEs                  |
| `--adobe`     | Include Adobe CVEs released on Patch Tuesday          |
| `--sap`       | Include SAP Patch Tuesday CVEs                        |
| `--all`       | Run all of the above in one go                        |


## 📄 What You Get

After running, the tool will create an Excel file like:

Vulnerabilities-Jul-2025.xlsx

This spreadsheet contains:

    CVE ID

    Title / Category

    CVSS Score

    Whether it's Publicly Disclosed

    Whether it's Exploited

    Affected Products

    Vulnerability Publish Date

    Link to the original security bulletin

## ❓ Example

To get CVEs from all vendors for July 2025:
```cmd
python3 PatchTuesday.py --month Jul-2025 --all
```
To fetch only Microsoft and SAP:
```cmd
python3 PatchTuesday.py --month Jul-2025 --microsoft --sap
```


## 💡 Tips

    The first run may take a few seconds to install packages.

    Make sure you're connected to the internet.

## 📬 Questions?
No questions allowed. 


