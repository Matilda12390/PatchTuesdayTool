# 🛠️ Patch Tuesday CVE Report Tool

This tool gathers CVE (Common Vulnerabilities and Exposures) information from **Microsoft**, **Adobe**, and **SAP**, checks exposure status on **Feedly**, and exports a spreadsheet of vulnerabilities for a selected month.

You can now run it directly from **GitHub Actions** (no setup required), or run it manually on your own machine if you prefer.

---

## 🚀 Running with GitHub Actions (Recommended)

1. Go to the **Actions** tab in this repository.
2. The script is scheduled to run every second Tuesday of the month. The most recent entry is the last scheduled run. 
6. Download the results:
   - Scroll to the bottom of the run → **Artifacts → excel-files.zip**
   - Inside you’ll find the generated Excel file(s)
---

## 💻 How to Run Manually

If you don’t want to use GitHub Actions, you can still run the script yourself.  

### Requirements
- Windows 10/11 or Linux
- Python 3.12+ 
- Internet connection (for fetching advisories and enrichment data)

---

1. Install [Python](https://www.python.org/downloads/) (tick **Add to PATH**).
2. Download this repo and extract it.
3. Open a terminal/command prompt in the folder:
   ```sh
   pip install -r requirements.txt
   python PatchTuesday.py Jul-2025 --microsoft --sap

   ```

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
| `--oracle`    | Include Oracle Patch Tuesday CVEs (Quarterly release) |
| `--all`       | Run all of the above in one go                        |


## 📄 What You Get

After running, the tool will create an Excel file like:

VENDOR-Jul-2025.xlsx

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


## 📬 Questions?
No questions allowed. 


