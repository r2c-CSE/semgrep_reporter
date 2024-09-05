from semgrep_reporter.api import get_deployment_slug, get_projects, get_project_findings
from semgrep_reporter.datafields import SEVERITIES, STATUSES
import logging

logger = logging.getLogger(__name__)


def assemble_report_data(api_token, tag=None, aggregate=False, important=False):
    # Get the organization identifier and use it to query list of projects in org
    slug = get_deployment_slug(api_token)
    logger.info("Accessing org: " + slug)

    logger.info("Getting list of projects in org: " + slug)
    projects = get_projects(api_token, slug)

    # If user provides a tag, filter the projects with that tag.
    if tag is not None:
        projects = filter_by_tag(projects, tag)

    report_datasets = []
    if aggregate:
        # Aggregate findings for all projects into one dataset for one report across all projects.
        findings = get_all_findings(api_token, slug, projects)
        report_name = "All Projects in " + slug
        report_datasets.append({"project": report_name, "findings": findings})
    else:
        # Collect findings data to be reported per project
        for project in projects:
            findings = get_project_findings(api_token, slug, project["name"])
            report_datasets.append({"project": project["name"], "findings": findings})

    # Filter by important findings. High severity and High or Medium Confidence.
    if important:
        logger.debug("FILTERING BY IMPORTANT")
        report_datasets = filter_by_important(report_datasets)

    # Flesh out project data with summaries for severity, vuln class, and owasp category
    report_datasets = tabulate_summary_data(report_datasets)

    return report_datasets


# Filters list of projects by a tag.
def filter_by_tag(projects, tag):
    filtered_projects = []

    for project in projects:
        if tag in project.get("tags", []):
            filtered_projects.append(project)

    return filtered_projects


# Gets all the findings for all the projects and returns array of each set of findings.
def get_all_findings(token, slug, projects):
    findings = []

    for project in projects:
        logging.debug(
            f"Currently processing project/repo: {project['name']}  with the following tags {project['tags']}"
        )
        findings += get_project_findings(token, slug, project["name"])

    return findings


# Filters findings in multiple datasets by 'Importance'
# Important findings are either high severity or high/medium confidence
def filter_by_important(report_datasets):
    filtered_datasets = []
    for dataset in report_datasets:

        filtered_findings = [
            finding
            for finding in dataset["findings"]
            if finding["severity"] == "high"
            and (finding["confidence"] == "high" or finding["confidence"] == "medium")
        ]
        filtered_datasets.append(
            {"project": dataset["project"], "findings": filtered_findings}
        )

    return filtered_datasets


# Sums the occurences of severity, status, owasp category, and vulnerability class.
# Adds these sums to each dataset as a summary statistic.
def tabulate_summary_data(datasets):
    for data in datasets:
        if len(data["findings"]) == 0:
            logger.info(f"No SAST findings found for - {data['project']}")
        findings = data["findings"]
        data["severity_status"] = tabulate_severity_status(findings)
        data["owasp_counts"] = tabulate_owasp_top_10(findings)
        data["vuln_class_counts"] = tabulate_vuln_classes(findings)
        # logging.debug(
        #     f"severity_and_status_counts in repo: {data['project']} - {data['severity_status']}"
        # )
    return datasets


# Sums the severity and status of each finding.
def tabulate_severity_status(
    findings,
    finding_severities=SEVERITIES,
    finding_statuses=STATUSES,
):
    # Initialize counters for each severity level and each status within that level

    counts = {}
    for level in finding_severities:
        counts[level] = {}
        for status in finding_statuses:
            counts[level][status] = 0

    # Iterate through each item in the data
    for finding in findings:
        severity = finding.get("severity")  # Get the severity of the current item
        status = finding.get("status")  # Get the status of the current item

        # Check if the severity and status are recognized, then increment the appropriate counter
        if severity in counts and status in counts[severity]:
            counts[severity][status] += 1
    logger.debug("Severity Status Count")
    logger.debug(counts)
    return counts


# Sums the occurenece of each vulnerability class in the findings.
def tabulate_vuln_classes(findings, severities=["high"], statuses=["open"]):
    counts = {}
    for finding in findings:
        owasp_top10_categories = finding["rule"]["owasp_names"]
        if finding["severity"] in severities and finding["status"] in statuses:
            for owasp_cat in owasp_top10_categories:
                if owasp_cat in counts:
                    counts[owasp_cat] += 1
                else:
                    counts[owasp_cat] = 1

    return counts


# Sums the occurence of each OWASP top 10 category in the findings.
def tabulate_owasp_top_10(findings, severities=["high"], statuses=["open"]):
    counts = {}
    for finding in findings:
        vulnerability_classes = finding["rule"]["vulnerability_classes"]
        if finding["severity"] in severities and finding["status"] in statuses:
            for vuln_class in vulnerability_classes:
                if vuln_class in counts:
                    counts[vuln_class] += 1
                else:
                    counts[vuln_class] = 1
    return counts


def assign_security_grade(high, medium, low):
    """
    Assigns a security grade based on the number of high, medium, and low vulnerabilities.

    :param high: Number of high vulnerabilities.
    :param medium: Number of medium vulnerabilities.
    :param low: Number of low vulnerabilities (currently not used in grading logic).
    :return: Security grade as a string (A, B, C, or D).
    """
    # Criteria for grade A
    if high == 0 and medium < 10:
        return "A"
    # Criteria for grade B
    elif high < 5 and medium < 25:
        return "B"
    # Criteria for grade C
    elif high < 10 and medium < 50:
        return "C"
    # Criteria for grade D
    elif high < 25 and medium < 100:
        return "D"
    # If none of the above criteria are met, the security grade is considered to be below D.
    else:
        return "F"
