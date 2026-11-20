# OSINT-Website-Analysis
Python-based OSINT tool for website analysis using multiple threat intelligence APIs.
# OSINT Website Analysis Tool

## Project Description
This project is a Python-based OSINT (Open Source Intelligence) tool designed to analyze a target website using multiple threat intelligence APIs.

It collects website security and domain information, compares the results, and exports the findings into an Excel report.

## OSINT Tools
1. VirusTotal – Website reputation and malware detection.
2. WhoisXML API – Domain registration information.
3. AlienVault OTX – Threat intelligence information.
4. Google Safe Browsing – Checks URLs against known web threats.
5. Fifth OSINT tool – Pending integration.

## Technologies Used
- Python
- REST APIs
- Requests
- Pandas
- OpenPyXL
- Python-dotenv

## Project Files
- `main.py` – Main Python program.
- `requirements.txt` – Required Python libraries.
- `OSINT_Website_Analysis_Report.xlsx` – Excel analysis report.

## Installation

Install the required libraries:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project directory and configure your API keys:

```env
VT_API_KEY=your_virustotal_api_key
WHOIS_API_KEY=your_whoisxml_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key
GOOGLE_API_KEY=your_google_api_key
```

## Run the Program

```bash
python main.py
```

Enter the target website when prompted.

## Output
The program retrieves results from the configured OSINT APIs and displays the findings. The analysis results are compared in an Excel workbook.

## Important Note
The current demonstration was tested using `example.com`. Four APIs are currently integrated and working. The fifth tool is pending integration.

## Author
Mailah Tariq

## Academic Purpose
Developed as part of an OSINT laboratory assignment.
