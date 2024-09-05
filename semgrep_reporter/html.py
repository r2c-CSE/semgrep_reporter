import os
from datetime import datetime
import logging
import pandas as pd
import dominate
from dominate.util import raw
from dominate.tags import (
    div,
    script,
    link,
    h1,
    h2,
    table,
    tr,
    th,
    td,
    a,
)
from semgrep_reporter.css import report_styling, security_grade_class
from semgrep_reporter.datafields import SEVERITIES, STATUSES
from semgrep_reporter.image import (
    report_image,
    semgrep_logo,
)
from semgrep_reporter.findings import assign_security_grade

logger = logging.getLogger(__name__)


def generate_combined_html(datasets, project_name, report_images, out_folder):
    report_title = "Semgrep SAST Scan Report for " + project_name
    formatted_now = datetime.now().strftime("%Y-%m-%d %H:%M")

    doc = dominate.document(title=report_title)
    with doc.head:
        script(type="text/javascript", src="https://cdn.plot.ly/plotly-latest.min.js")
        script(type="text/javascript", src="https://code.jquery.com/jquery-3.5.1.js")
        script(
            type="text/javascript",
            src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js",
        )
        link(
            rel="stylesheet",
            href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css",
        )
        report_styling()
    with doc:
        div(cls="spacer")
        semgrep_logo()
        report_header(report_title, formatted_now)
        div(cls="break-always")
        summary_table(datasets)
        div(cls="break-always")

    # Images
    for single_image in report_images:
        doc.add(
            report_image(
                single_image["title"],
                single_image["id"],
                single_image["alt"],
                single_image["filepath"],
            )
        )
    doc.add(div(cls="break-always"))

    # Now add all the existing reports to the end of the document.
    for item in sorted(os.listdir(out_folder)):
        if item.endswith(".html"):
            file_path = os.path.join(out_folder, item)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Extract body content (simple approach, could be improved with an HTML parser for robustness)
                body_content = content.split("<body>", 1)[-1].rsplit("</body>", 1)[0]
                doc.add(raw(body_content))
                doc.add(div(cls="break-always"))
    return doc.render()


def generate_html_sast(project_name, findings):
    report_title = "Semgrep SAST Scan Report for Repository: " + project_name

    doc = dominate.document(title=report_title)
    with doc.head:
        link(
            rel="stylesheet",
            href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css",
        )
        report_styling()
    with doc.body:
        div(cls="spacer")
        semgrep_logo()
        report_header(report_title, datetime.now().strftime("%Y-%m-%d %H:%M"))
        div(cls="spacer")
        severity_count_table(findings)
        div(cls="break-after")
        finding_tables(findings)

    return doc.render()


def generate_summary_table(
    datasets, severity_levels=SEVERITIES, finding_statuses=STATUSES
):
    """
    Generates HTML table rows (<tr>) for a DataFrame, including a header row.
    Each 'Security Grade' cell gets colored based on its value, and certain columns are centered.

    :param df: DataFrame with columns including 'Project Name', 'Security Grade', etc.
    :return: String with HTML content for table rows.
    """
    divider = "  "
    headers = ["Project Name", " ", "Security Grade"]
    center_columns = ["Security Grade"]
    for level in severity_levels:
        headers.append(divider)
        for status in finding_statuses:
            # Note: status control
            if status == "fixing" or status == "reviewing":
                continue
            headers.append(status.capitalize() + "-" + level.upper())
            center_columns.append(status.capitalize() + "-" + level.upper())
        divider += " "

    rows = []

    for dataset in datasets:
        divider = "  "
        row = {"Project Name": dataset["project"], " ": " ", "Security Grade": ""}
        for level in severity_levels:
            row[divider] = " "
            for status in finding_statuses:
                # Note: status control
                if status == "fixing" or status == "reviewing":
                    continue
                row[status.capitalize() + "/" + level.capitalize()] = 0
            divider += " "
        for severity in dataset["severity_status"]:
            for status in dataset["severity_status"][severity]:
                if severity in severity_levels and status in finding_statuses:

                    count = dataset["severity_status"][severity][status]
                    reported_status = status

                    # Note Status Control
                    if reported_status == "fixing" or reported_status == "reviewing":
                        reported_status = "open"

                    row_key = reported_status.capitalize() + "/" + severity.capitalize()
                    if row_key in row:
                        row[row_key] += count
                    else:
                        row[row_key] = count
        row["Security Grade"] = "N/A"
        if "Open/High" in row and "Open/Medium" in row and "Open/Low" in row:
            row["Security Grade"] = assign_security_grade(
                row["Open/High"], row["Open/Medium"], row["Open/Low"]
            )
        rows.append(row)

    df = pd.DataFrame(rows)
    logger.debug(df)
    df = df.sort_values(by="Open/High", ascending=False)

    sum_table = table(id="myDataTable", cls="my_table")
    header_html = tr()
    for header in headers:
        if header in center_columns:
            header_html.add(th(header, cls="center-text"))
        elif header.isspace():
            header_html.add(th(" "))
        else:
            header_html.add(th(header))
    sum_table.add(header_html)

    for index, row in df.iterrows():
        row_html = tr()
        for col, header in zip(df.columns, headers):
            cell_classes = ""
            if header.isspace():
                cell_classes += "divider-cell"
            if header == "Security Grade":
                cell_classes += security_grade_class(row["Security Grade"])
            if header in center_columns:
                cell_classes += " center-text"
            row_html.add(td(row[col], cls=cell_classes))

        sum_table.add(row_html)

    return sum_table


def summary_table(datasets, severity_levels=SEVERITIES, finding_statuses=STATUSES):
    contain = div(cls="container-table centered-table")
    summary = table(id="myTable", cls="my_table")
    summary.add(generate_summary_table(datasets, severity_levels, finding_statuses))
    contain.add(summary)
    contain.add(
        script(
            """
            $(document).ready(function () {{
                $('#myTable').DataTable({{
                }});
            }});
            """
        )
    )
    return contain


# @div(cls="container")
def report_header(title_text, time):
    logger.debug("Title " + title_text)
    contain = div(cls="container")
    contain.add(h1(title_text, cls="center-text", id="sast"))
    contain.add(
        h2(
            "Report Generated at " + time,
            cls="center-text",
            id="reporttime",
        )
    )
    return contain


def severity_count_table(findings: pd.DataFrame, severity_levels=SEVERITIES):
    topnav = div(cls="topnav")
    topnav.add(h2("SAST Scan Summary", cls="center-text", id="sast-summary"))
    count_table = table(
        tr([th("Vulnerability Severity"), th("Vulnerability Count")]),
        border="1",
        cls="centered-table",
    )

    for level in severity_levels:
        row = tr()
        row.add(
            td(
                a(
                    "Findings- SAST " + level.capitalize() + " Severity",
                    href="#sast-" + level,
                )
            )
        )
        row.add(td(len(findings.loc[(findings["severity"] == level)])))
        count_table.add(row)
    topnav.add(count_table)
    return topnav


def finding_tables(findings, severity_levels=SEVERITIES):
    contain = div(cls="container")
    for level in severity_levels:
        contain.add(
            div(
                h2(
                    "Findings Summary- " + level.capitalize() + " Severity",
                    id="sast-" + level,
                ),
                cls="heading",
            )
        )
        contain.add(
            div(
                table(
                    raw(
                        findings.loc[(findings["severity"] == level)].to_html(
                            index=False,
                            table_id="table" + level,
                            render_links=True,
                            escape=False,
                            classes="my_table",
                        )
                    ),
                    cls="full-width",
                ),
                cls="container",
            )
        )
        contain.add(div(cls="break-after"))
    return contain


# HTML escape the Finding Description Column
def escape_html_description(row):
    s = row["Finding Description & Remediation"]
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
