Nessus XML to Excel Parser (v2, directory input update)
====================================================

Requirements
------------
Python 3.10+ and openpyxl:
    pip install -r requirements.txt

Usage
-----
Single file (unchanged):
    python nessus2excel.py scan.nessus -o findings.xlsx

Multiple files, separated by spaces (not commas):
    python nessus2excel.py foo.nessus bar.nessus etc.nessus -o findings.xlsx

All .nessus files in a directory:
    python nessus2excel.py -dir /customer_nessus/ -o customer_findings.xlsx
    python nessus2excel.py --dir "C:\Customer Scans" -o customer_findings.xlsx

Combine explicit files and directories, or repeat -dir:
    python nessus2excel.py extra.nessus -dir scans1 -dir scans2 -o findings.xlsx

Glob patterns and explicit .xml files remain supported:
    python nessus2excel.py "scans/*.nessus" other.xml -o findings.xlsx

Include informational findings (excluded by default):
    python nessus2excel.py -dir scans --min-severity 0 -o findings.xlsx

Input behavior
--------------
- No fixed file-count limit; 16 or more reports can feed one workbook.
- Directory mode includes .nessus files directly inside the directory, with
  case-insensitive extensions, sorted by filename. It does not recurse.
- Explicit files retain their supplied order; directory files are appended.
- The same resolved file path is included only once, even if selected through
  both an explicit path/glob and a directory.
- Findings repeated across different reports remain separate rows, as in v2.
- Missing inputs, invalid/empty directories and malformed XML fail before the
  workbook is written. Existing output is retained on these input failures.
- Paths containing spaces must be quoted. Separate filenames with spaces.
- Memory and Excel worksheet limits still apply to very large report sets.

Output (unchanged)
------------------
One workbook, with one "Nessus Findings" sheet and these ten columns:
Host IP, Host Name, Operating System, Severity, Synopsis, Description,
Solution, Plugin Output, See Also, CVE Numbers.

Existing severity sorting, formatting, column widths, filters, frozen header,
minimum severity (default 1), console severity totals and default output path
(nessus_findings.xlsx) are preserved.

Files
-----
nessus2excel.py       Current parser
OLD_No_totals.py      Historical script (unchanged)
requirements.txt     Dependencies
tests/test_inputs.py Input regression tests

Run tests from this directory:
    python -m unittest discover -s tests -v

Author
------
Apt4hax
