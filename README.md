# PatchTuesdayExport

# 🛠️ Patch Tuesday CVE Report Tool

This tool gathers CVE (Common Vulnerabilities and Exposures) information from Microsoft and Adobe, checks exposure status on Feedly, and exports a spreadsheet of vulnerabilities for a selected month.

No technical knowledge needed — just follow the simple steps below.

---

## ✅ What You Need

- **Python 3.x installed** on your computer  
  If you don’t have it, download it from: https://www.python.org/downloads/

You **do not need to install anything else manually** — the tool handles it for you.

---

## 📦 What's Included
```
PatchTuesdayTool/
├── PatchTuesday.py ← Main script
├── requirements.txt ← Python dependencies
├── run_patchtuesday.bat ← Run this on Windows
├── README.md ← You are here
```

## ▶️ How to Use

### 🪟 Windows Users

1. **Unzip** the folder if it's in a `.zip` file
2. **Double-click** `run_patchtuesday.bat`

Or you can open a Command Prompt and run:

```cmd
run_patchtuesday.bat --month Jul-2025 --microsoft --adobe
```

⚙️ Available Options
| Option        | Description                                       |
| ------------- | ------------------------------------------------- |
| `--month`     | (Required) The month to check, format: `Jul-2025` |
| `--microsoft` | Include Microsoft Patch Tuesday CVEs              |
| `--adobe`     | Include Adobe CVEs released on Patch Tuesday      |

📄 What You Get

After running, the tool will create an Excel file like:

Vulnerabilities-Jul-2025.xlsx

This spreadsheet contains:

    CVE ID

    Title / Category

    CVSS Score

    Whether it's Publicly Disclosed

    Whether it's Exploited

    Affected Products

    Link to the original security bulletin

❓ Example

To get Microsoft and Adobe CVEs for July 2025:

run_patchtuesday.bat --month Jul-2025 --microsoft --adobe

💡 Tips

    You only need to run run_patchtuesday.bat — the tool sets everything up for you.

    The first run may take a few seconds to install packages.

    Make sure you're connected to the internet.

📬 Questions?
No questions allowed. 
