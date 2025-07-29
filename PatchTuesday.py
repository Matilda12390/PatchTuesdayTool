import requests
import sys
import argparse
import time
from datetime import datetime, timedelta
import calendar
from openpyxl import Workbook
from openpyxl.styles import Font
from bs4 import BeautifulSoup
import re

FEEDLY_URL = "https://feedly.com/cve/{}"

MSRC_API_CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{}"
MSRC_API_CVE_URL = "https://msrc.microsoft.com/update-guide/en-US/vulnerability/{}"
HEADERS = {"Accept": "application/json"}

ADOBE_SECURITY_BULLETIN_URL = "https://helpx.adobe.com/au/security/security-bulletin.html"
ADOBE_BASE_URL = "https://helpx.adobe.com"

SAP_SECURITY_NOTES_URL = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{}.html"

# General reusable functions across Vendors
# - save_to_excel - given the rows and filename, save the file as xlsx
# - get_patch_tuesday - given the users input, get the date of patch tuesday that month
# - make_vendor_request_JSON - just makes the API request and returns the response in JSON
# - make_vendor_request_HTML - for web scraping, just grab the website content as HTML
# - check_feedly - given a CVE, get the POC/Exploited status from Feedly
# - enrich_cves_with_feedly - check a list of CVEs with Feedly 


def save_to_excel(rows, filename):
    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    headers = ["CVE", "Title", "CVSS Score", "Public PoC", "Exploited", "Affected Products", "Release Notes"]
    ws.append(headers)

    for row_data in rows:
        ws.append([row_data.get(h, "") for h in headers])

        current_row = ws.max_row
        url_cell = ws.cell(row=current_row, column=len(headers))  # last column (Release Note)

        url = row_data.get("Release Notes")
        if url:
            url_cell.value = "Release Note"          # display text
            url_cell.hyperlink = url                  # actual hyperlink
            url_cell.font = Font(underline="single", color="0000FF")

    wb.save(filename)

def get_patch_tuesday(target_year, target_month):
    # Find the first day of the month
    first_day = datetime(target_year, target_month, 1)
    # Get the weekday of the first day (0=Monday, 1=Tuesday, ...)
    first_weekday = first_day.weekday()

    # Calculate how many days until the first Tuesday
    days_until_tuesday = (1 - first_weekday) % 7
    first_tuesday = first_day + timedelta(days=days_until_tuesday)

    # Add 7 days to get the second Tuesday (Patch Tuesday)
    patch_tuesday = first_tuesday + timedelta(days=7)
    return patch_tuesday.date()


def make_vendor_request_JSON(URL, month_selected):
    try:
        response = requests.get(URL, headers=HEADERS)
        response.raise_for_status()  # raises HTTPError for bad status codes
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            print(f"[404] Patch Tuesday release for month '{month_selected}' not found.")
        else:
            print(f"[HTTP {response.status_code}] Error fetching release '{month_selected}': {http_err}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error or invalid response: {e}")
        sys.exit(1)

def make_vendor_request_HTML(URL, month_selected):
    try:
        response = requests.get(URL)
        response.raise_for_status()  # raises HTTPError for bad status codes
        return response
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            print(f"[404] Patch Tuesday release for month '{month_selected}' not found.")
        else:
            print(f"[HTTP {response.status_code}] Error fetching release '{month_selected}': {http_err}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error or invalid response: {e}")
        sys.exit(1)

def check_feedly(cve):
    print(f"[*] Fetching Feedly enrichment for {cve}...")
    response = make_vendor_request_HTML(FEEDLY_URL.format(cve), "FEEDLY ERROR")
    soup = BeautifulSoup(response.text, "html.parser")

    # Look for <h3> containing "exploitation" (case-insensitive)
    exploitation_header = soup.find("h3", string=lambda s: s and "exploitation" in s.lower())

    no_poc_str = "There is no evidence that a public proof-of-concept exists."
    no_exploit_str = "There is no evidence of proof of exploitation at the moment."

    if not exploitation_header:
        # Exploitation section missing → default values
        public_poc = "No"
        exploited = "No"
    else:
        # Get the text content of the exploitation section (next sibling elements)
        # Sometimes next_sibling might be whitespace/newline, so use find_next() to get text
        section_text = ""
        next_el = exploitation_header.find_next()
        while next_el and next_el.name != "h3":  # stop at next <h3> or end
            if isinstance(next_el, str):
                section_text += next_el.strip() + " "
            elif next_el.name in ["p", "div", "span"]:
                section_text += next_el.get_text(separator=" ", strip=True) + " "
            next_el = next_el.find_next()

        section_text = section_text.lower()

        public_poc = "No" if no_poc_str.lower() in section_text else "Yes"
        exploited = "No" if no_exploit_str.lower() in section_text else "Yes"

    return {
        "CVE": cve,
        "Public PoC": public_poc,
        "Exploited": exploited
    }


def enrich_cves_with_feedly(cve_list):
    for cve_entry in cve_list:
        cve_id = cve_entry.get("CVE")
        if not cve_id:
            continue

        feedly_info = check_feedly(cve_id)

        # Add to the existing CVE record
        cve_entry["Public PoC"] = feedly_info["Public PoC"]
        cve_entry["Exploited"] = feedly_info["Exploited"]

        # Optional: avoid hammering Feedly too fast
        time.sleep(1)

# SAP specific functions
# - get_sap_cves - nice and easy, we scrape a single page of all the information in the table
# - start_sap_workflow - start of SAP hell
def start_sap_workflow(patch_tuesday_date, month_selected):
    print(f"[*] Fetching SAP Patch Tuesday data for {month_selected}...")
    sap_cves = get_sap_cves(month_selected)
    print(f"[*] SAP Patch Tuesday data for {month_selected} retrieved successfully")

    print(f"[*] Fetching Feedly enrichment... (this will take 1 second per CVE)")
    enrich_cves_with_feedly(sap_cves)
    print(f"[*] Feedly enrichment retrieved successfully!")

    filename = f"SAP-Patch-Tuesday-{month_selected}.xlsx"
    save_to_excel(sap_cves, filename)
    print(f"[+] Done. Output saved to '{filename}'.")



def get_sap_cves(month_selected):
    sap_cves = []

    try:
        # Convert 'Jul-2025' to 'july-2025' (SAP's required format for the URL).
        full_month = datetime.strptime(month_selected, "%b-%Y").strftime("%B-%Y").lower()
        response = make_vendor_request_HTML(SAP_SECURITY_NOTES_URL.format(full_month), month_selected)
        soup = BeautifulSoup(response.text, "html.parser")

        table = soup.find("table")
        if not table:
            print("[!] No SAP table found.")
            return []

        for row in table.find_all("tr")[1:]:  # Skip header row
            cols = row.find_all("td")
            if len(cols) < 4:
                continue

            note_link_tag = cols[0].find("a")
            release_note_url = note_link_tag["href"].strip() if note_link_tag and note_link_tag.has_attr("href") else ""

            # Title column: extract CVE and affected product
            title_col = cols[1]

            # Flatten all text and tags to check for non-CVE preamble
            first_significant_text = title_col.get_text(strip=True)
            first_cve_tag = title_col.find("a")

            if not first_cve_tag:
                continue

            # Only allow if the full title cell starts immediately with the CVE tag, skip any "Update to Security Note released on May 2025 Patch Day:"
            if not first_significant_text.startswith(f"[{first_cve_tag.get_text(strip=True)}]"):
                continue
            cve_id = first_cve_tag.get_text(strip=True).strip("[]") if first_cve_tag else "Unknown"
            title_text = title_col.get_text(" ", strip=True)

            # Extract product name
            product_match = re.search(r'Products?\s*.*?\s+(.*?)\s+Versions?',title_text,re.IGNORECASE | re.DOTALL)
            affected_product = product_match.group(1).strip() if product_match else "Unknown"


            # Remove CVE and product/version lines for a cleaner title
            title_lines = title_text.split("Product –")[0].strip()
            clean_title = re.sub(r"\[\s*CVE-\d{4}-\d{4,7}\s*\]\s*", "", title_lines).strip()

            # CVSS score
            cvss_score = cols[3].get_text(strip=True)

            # Build final row for Excel
            sap_cves.append({
                "CVE": cve_id,
                "Title": clean_title,
                "CVSS Score": cvss_score,
                "Publicly Disclosed": "Unknown",
                "Exploited": "Unknown",
                "Affected Products": affected_product,
                "Release Notes": release_note_url
            })

    except Exception as e:
        print(f"[!] Error parsing SAP CVEs: {e}")

    return sap_cves



# Adobe specific functions
# Adobe sucks
# - get_adobe_product_links - starting from the initial security bulletin table page, scrape all the product security adversories for the month
# - extract_adobe_cves - navigate to each product security adversory page to get the CVE details
# - extract_cve_details_from_bulletin - once on a product page, extract the vulnerability table from the page and all the CVE details
# - resolve_column_indices - helper function bc Adobe is not consistent on its header titles in its vuln tables
# - find_vuln_details_table - helper function to find the vuln details table on the webpage
# - convert_adobe_rows - convert the info we have on the adoble vulns to standard format for output
# - start_adobe_workflow - start adoble hell

def get_adobe_product_links(soup, patch_tuesday_date):
    product_links = []
    # Parse each row in the security bulletin table
    table = soup.find("table")  # only the first table
    if not table:
        print("[!] No table found on bulletin page.")
        return []

    rows = table.find_all("tr")[1:]  # skip header
    for row in rows:
        cols = row.find_all("td")
        if len(cols) < 3:
            continue

        title_cell = cols[0]
        original_date_str = cols[1].get_text(strip=True)

        # Try parsing the date
        try:
            original_date = datetime.strptime(original_date_str, "%m/%d/%Y").date()
        except ValueError:
            continue

        # Extract link and product name
        a_tag = title_cell.find("a", href=True)
        if not a_tag:
            continue

        href = a_tag["href"]
        product_url = href if href.startswith("http") else ADOBE_BASE_URL + href
        full_title = a_tag.get_text(strip=True)
        match = re.search(r"Security\s+update\s+available\s+for\s+(.+)$", full_title)
        product_name = match.group(1).strip() if match else full_title  # fallback
        if original_date == patch_tuesday_date:
            product_links.append({
                "Product": product_name,
                "URL": product_url,
                "Originally Posted": original_date_str
            })

    return product_links

def extract_adobe_cves(product_links):
    all_cves = []

    for entry in product_links:
        product = entry["Product"]
        url = entry["URL"]
        print(f"[+] Extracting detailed CVEs for {product}")
        detailed_cves = extract_cve_details_from_bulletin(product, url)
        all_cves.extend(detailed_cves)
    return all_cves

def extract_cve_details_from_bulletin(product_name, bulletin_url):
    try:
        response = make_vendor_request_HTML(bulletin_url, product_name)
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the table by header
        table = find_vuln_details_table(soup)
        if not table:
            print(f"[!] Could not locate 'Vulnerability Details' table on {bulletin_url}")
            return []

        rows = table.find_all("tr")
        if not rows:
            print(f"[!] No rows found in vulnerability details table at {bulletin_url}")
            return []
        
        # Extract header cells (first row), supporting <td> or <th> bc adobe sucks
        header_cells = rows[0].find_all(["td", "th"])
        headers = [cell.get_text(strip=True) for cell in header_cells]


        # Map expected columns
        expected_cols = {
            "vuln_cat": ["Vulnerability Category"],
            "impact": ["Vulnerability Impact"],
            "severity": ["Severity"],
            "cvss_score": ["CVSS base score"],
            "cvss_vector": ["CVSS vector"],
            "cve_number": ["CVE Numbers", "CVE Number", "CVE Number(s)"]  # <--- support all bc adobe sucks
        }

        col_map = resolve_column_indices(headers, expected_cols)

        # Check if any expected column is missing
        missing_cols = [k for k in expected_cols if k not in col_map]
        if missing_cols:
            print(f"[!] Missing columns {missing_cols} in table headers at {bulletin_url}")
            return []

        cve_details = []
        for row in rows:
            cells = row.find_all(["td", "th"])
            if len(cells) < len(col_map):
                continue

            vuln_cat    = cells[col_map["vuln_cat"]].get_text(strip=True)
            cvss_score  = cells[col_map["cvss_score"]].get_text(strip=True)
            cve_raw     = cells[col_map["cve_number"]].get_text(strip=True)


            # CVE Numbers may be separated by commas, spaces, or newlines
            cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", cve_raw, re.IGNORECASE)

            for cve in cve_list:
                cve_details.append({
                    "CVE": cve,
                    "Title": vuln_cat,
                    "CVSS Score": cvss_score,
                    "Publicly Disclosed": "Unknown",  
                    "Exploited": "Unknown",           
                    "Affected Products": product_name,
                    "Release Notes": bulletin_url
                })


        return cve_details

    except Exception as e:
        print(f"[!] Failed to extract detailed CVE info from {bulletin_url}: {e}")
        return []
    
def resolve_column_indices(header_cells, expected_cols):
    col_map = {}
    for idx, header in enumerate(header_cells):
        header_clean = header.lower().strip()
        for key, aliases in expected_cols.items():
            for alias in aliases:
                if alias.lower() == header_clean:
                    col_map[key] = idx
                    break
    return col_map
    
def find_vuln_details_table(soup):
    # Look for all <h2> elements
    for h2 in soup.find_all("h2"):
        if "vulnerability details" in h2.get_text(strip=True).lower():
            # Search forward in the document for the first <table>
            next_el = h2
            while next_el:
                next_el = next_el.find_next()
                if next_el.name == "table":
                    return next_el
    return None


def start_adobe_workflow(patch_tuesday_date, month_selected):
    print(f"[*] Fetching Adobe Patch Tuesday data for {month_selected}...")
    response = make_vendor_request_HTML(ADOBE_SECURITY_BULLETIN_URL, month_selected)
    print(f"[*] Adobe Patch Tuesday data for {month_selected} retrieved successfully")
    soup = BeautifulSoup(response.text, "html.parser")
    product_links = get_adobe_product_links(soup, patch_tuesday_date)
    all_cves = extract_adobe_cves(product_links)
    print(f"[*] Fetching Feedly enrichment... (this will take 1 second per CVE)")
    enrich_cves_with_feedly(all_cves)
    print(f"[*] Feedly enrichment retrieved successfully!")
    filename = f"Adobe-Patch-Tuesday-{month_selected}.xlsx"
    save_to_excel(all_cves, filename)
    print(f"[+] Done. Output saved to '{filename}'.")



# Microsoft specific functions
#  - resolve_product_name_microsoft - the affected products are just listed as IDs in the CVE information returned by the API, gotta convert to product name by checking a different section of the API response
# - extract_vulnerability_info_microsoft - get all the juicy information in a microsoft specific way
# - start_microsoft_workflow - start of microsoft hell

def resolve_product_name_microsoft(product_id, doc):
    for product in doc.get("ProductTree", {}).get("FullProductName", []):
        if product["ProductID"] == product_id:
            return product["Value"]
    return product_id

def extract_vulnerability_info_microsoft(doc, patch_tuesday_date):
    rows = []
    start_of_month = patch_tuesday_date.replace(day=1)

    for vuln in doc.get("Vulnerability", []):
        # check RevisionHistory[0]["Date"] to get the date published 
        rev_history = vuln.get("RevisionHistory", [])
        if not rev_history:
            continue
        try:
            pub_date_str = rev_history[0]["Date"]
            pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00")).date()
        except Exception:
            continue  # skip if date is malformed

        if not (start_of_month <= pub_date <= patch_tuesday_date): # MAY BREAK - if you need all vulns in a month with no end date, replace line with if not (start_of_month <= pub_date)
            continue  # skip CVEs not published from the start of the month to patch tuesday aka not included in the security update notes. We specify an end date in case the script is being run later in the month

        cve = vuln.get("CVE", "N/A")
        disclosed = "No"
        exploited = "No"

        for threat in vuln.get("Threats", []):
            desc = threat.get("Description", {}).get("Value", "")
            if "Publicly Disclosed:" in desc and "Exploited:" in desc:
                # Example: "Publicly Disclosed:No;Exploited:Yes;..."
                parts = dict(item.split(":") for item in desc.split(";") if ":" in item)
                disclosed = parts.get("Publicly Disclosed", "No")
                exploited = parts.get("Exploited", "No")
                break 


        cvss_base = "N/A"
        for score in vuln.get("CVSSScoreSets", []):
            if "BaseScore" in score:
                cvss_base = score["BaseScore"]
                break

        title = vuln.get("Title", {}).get("Value", "N/A")

        product_names = set()
        for product_status in vuln.get("ProductStatuses", []):
            for pid in product_status.get("ProductID", []):
                product_name = resolve_product_name_microsoft(pid, doc)
                product_names.add(product_name)

        release_note = MSRC_API_CVE_URL.format(cve)

        rows.append({
            "CVE": cve,
            "Title": title,
            "CVSS Score": cvss_base,
            "Public PoC": disclosed,
            "Exploited": exploited,
            "Affected Products": ", ".join(sorted(product_names)),
            "Release Notes": release_note
        })

    return rows

def start_microsoft_workflow(year, month_abbr, patch_tuesday_date):
    # Normalize to Microsoft's expected ID format: 2025-Jul
    month_normalized = f"{year}-{month_abbr}"
    
    print(f"[*] Fetching Microsoft Patch Tuesday data for {month_normalized}...")
    doc = make_vendor_request_JSON(MSRC_API_CVRF_URL.format(month_normalized), month_normalized)
    print(f"[*] Microsoft Patch Tuesday data for {month_normalized} retrieved successfully")
    rows = extract_vulnerability_info_microsoft(doc,patch_tuesday_date)

    filename = f"Microsoft_Patch_Tuesday_{month_abbr}-{year}.xlsx"
    save_to_excel(rows, filename)
    print(f"[+] Done. Output saved to '{filename}'.")

# main is main

def main():
    parser = argparse.ArgumentParser(description="Fetch Patch Tuesday vulnerability data and export to Excel.")
    parser.add_argument("--microsoft", action="store_true", help="Fetch data from Microsoft CVRF API feed")
    parser.add_argument("--adobe", action="store_true", help="Fetch data from Adobe Security Bulletin and enrich with Feedly")
    parser.add_argument("--sap", action="store_true", help="Fetch data from SAP Security Notes and enrich with Feedly")
    parser.add_argument("--all", action="store_true", help="Get all data from Microsoft, Adobe and SAP")
    parser.add_argument("month", help="Target month in format e.g. Jul-2025")

    args = parser.parse_args()

    if not args.month:
        print("Error: You must provide a month in the format 'Jul-2025'.")
        sys.exit(1)
    
    month_selected = args.month
    month_abbr, year = month_selected.split("-")
    patch_tuesday_date = get_patch_tuesday(int(year), datetime.strptime(month_abbr, "%b").month)

    # If --all is set, run everything
    if args.all:
        start_microsoft_workflow(year, month_abbr, patch_tuesday_date)
        start_adobe_workflow(patch_tuesday_date, month_selected)
        start_sap_workflow(patch_tuesday_date, month_selected)
    # If at least one individual flag is set
    elif args.microsoft or args.adobe or args.sap:
        if args.microsoft:
            start_microsoft_workflow(year, month_abbr, patch_tuesday_date)
        if args.adobe:
            start_adobe_workflow(patch_tuesday_date, month_selected)
        if args.sap:
            start_sap_workflow(patch_tuesday_date, month_selected)
    # No valid vendor flag passed
    else:
        print("Error: Please specify a vendor. Supported options: --microsoft  --adobe  --sap  --all")
        sys.exit(1)

if __name__ == "__main__":
    main()
