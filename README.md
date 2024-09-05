# Semgrep SAST Scan Report Generator

## Overview

This script automates the process of generating Security Static Analysis (SAST) reports for projects managed under a specified organization in Semgrep. It fetches project data, analyzes security findings, and compiles detailed reports in various formats including JSON, CSV, XLSX, HTML, and PDF. The script supports filtering findings based on severity and allows for comprehensive reporting by combining individual project findings into a single overview.

[Example PDF Report](https://github.com/r2c-CSE/semgrep-reporter/reports/1725511917/combined_output-1725511917.pdf)

[Example HTML Report](https://github.com/r2c-CSE/semgrep-reporter/reports/1725511917/combined_output-1725511917.html)

## Features

- Fetch projects and findings from Semgrep based on project tag.
- Generate detailed findings reports in JSON, CSV, XLSX, HTML, and PDF formats.
- Combine reports from multiple projects into a single comprehensive report.
- Filter findings based on severity to focus on the most critical issues.
- Automated report generation with timestamping for historical tracking.
- Provides a security grade to each repository based on number of High, Medium and Low `Open` vulnerabilities found
- Create a bar graph showing the top 15 repos by number of High, Medium and Low `Open` vulnerabilities 
- Create a bar graph showing the top 15 repos by number of High, Medium and Low `Fixed` vulnerabilities

## Prerequisites

- Python 3.11+
- pip
- pipx: You can install pipx with `pip install pipx`
- A valid Semgrep API web token set as an environment variable `SEMGREP_API_WEB_TOKEN`

## Installation

1. Ensure Python 3, pip, and pipx are installed.
2. Clone this repository. 
3. Run pipx at the root of this repository to install semgrep_reporter CLI tool and add it to the PATH:

`pipx install .`

4. You can now run the reporting tool. See the usage documentation below.

`semgrep_reporter <options>`

## Configuration
Before running the script, you must set up the `SEMGREP_API_WEB_TOKEN` environment variable with your Semgrep API token:

`export SEMGREP_API_WEB_TOKEN='your_api_token_here'`

Generate your `SEMGREP_API_WEB_TOKEN` from https://semgrep.dev/orgs/-/settings/tokens. Ensure that the box `Web API` is checked when creating the token.

## Usage
Run the script from the command line, specifying the tag of the projects you want to generate reports for:

```
usage: semgrep_reporter [-h] [-t TAG] [-i] [--combine] [--agg] [--json] [--csv] [--html] [--pdf] [--xlsx] [--all] [--log-level {ALL,DEBUG,INFO,WARNING,ERROR}]

Generates CSV, HTML, and PDF reports from your Semgrep Cloud Platform data.

options:
  -h, --help            show this help message and exit
  -t TAG, --tag TAG     Use to report on all projects with this tag.
  -i, --important       Report on important findings only.
  --combine             Generate an additional report combining and summarizing all of the other reports.
  --agg                 Aggregate findings from all projects into a single report.
  --json                Set to create JSON files of findings.
  --csv                 Set to create CSV files of findings.
  --html                Set to create HTML reports.
  --pdf                 Set to create PDF reports.
  --xlsx                Set to create Excel reports.
  --all                 Set flag to generate all reports and output formats.
  --log-level {ALL,DEBUG,INFO,WARNING,ERROR}
                        Set the level of logging during report generation. Options include DEBUG, INFO, WARNING, ERROR, or choose ALL for all levels of logging.
```

## The script will perform the following actions:

* Fetch all projects in the Semgrep organization. Or, just the project's associated with the specified tag.
* Generate findings reports for each project in the specified formats.
* Combine individual project reports into comprehensive reports.
* Save all reports to the directory `./reports/<timestamp_of_report>/`

## Output
The script saves generated reports in a dynamically created directory under reports/ based on the current epoch time. You will find the following files for each project and combined reports:
* Individual project findings in the specified JSON, CSV, XLSX, HTML, and/or PDF formats.
* Combined reports for all projects in JSON, HTML, and/or PDF formats.
* A summary HTML report providing an overview of findings across all projects.
