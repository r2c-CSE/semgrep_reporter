import os
import logging
import json
import pandas as pd
from weasyprint import HTML
from semgrep_reporter.fileutil import (
    init_out_file,
    combine_html_files,
    combine_json_files,
    combine_pdf_files,
    json_to_df,
    load_findings_df,
)
from semgrep_reporter.html import generate_html_sast

from semgrep_reporter.image import (
    create_bar_graph_fixed_vulns,
    create_bar_graph_open_vulns,
    create_heatmap_owasp_top10_categories,
    create_heatmap_vulnerability_classes,
)

logger = logging.getLogger(__name__)


# Generates reports for each dataset in the specified formats.
def generate_reports(
    report_datasets, out_folder, combined, json, html, csv, pdf, xlsx, tag=None
):
    for dataset in report_datasets:
        # logger.debug("Reporting on this dataset")
        # logger.debug(dataset)
        name = dataset["project"]
        # Generate JSON report of findings that will be used as the basis for all other formats
        json_filepath = generate_json_report(dataset, out_folder)
        logger.debug("%s", json_filepath)

        if csv:
            generate_csv_report(name, json_filepath, out_folder)

        if xlsx:
            generate_xlsx_report(name, json_filepath, out_folder)

        if html or pdf:
            html_filepath = generate_html_report(name, json_filepath, out_folder)

            if pdf:
                generate_pdf_report(name, html_filepath, out_folder)

            if not html and os.path.exists(html_filepath):
                os.remove(html_filepath)

        if not json and os.path.exists(json_filepath):
            os.remove(json_filepath)

    if combined:
        combine_reports(
            report_datasets,
            out_folder,
            json,
            html,
            csv,
            pdf,
            xlsx,
            tag=tag,
        )
    return


def combine_reports(datasets, out_folder, json, html, csv, pdf, xlsx, tag=None):
    if json:
        logging.info(f"starting process to combine JSON files")
        combine_json_files(out_folder, tag)
        logging.info(f"finished process to combine JSON files")

    # TODO: combine CSV files
    #  if csv:
    #      combine_csv_files(output_folder, tag)

    if pdf:
        logging.info(f"starting process to combine PDF files")
        combine_pdf_files(out_folder, tag)
        logging.info(f"finished process to combine PDF files")

    if html:
        logging.info(f"starting process to combine HTML files")
        output_filename = f"combined_output_{tag}.html"  # The name of the output file
        combine_html_files(datasets, out_folder, tag)
        logging.info(f"finished process to combine HTML files")

    # TODO: combine xlsx files
    # if xlsx:
    #     combine_xlsx_files(out_folder, tag)
    return


# Generate JSON file of findings for each dataset
def generate_json_report(dataset, out_folder):
    json_filepath = init_out_file(out_folder, dataset["project"], ".json")
    logger.info(
        f"starting process to create JSON data for the reports for {dataset['project']}"
    )

    with open(json_filepath, "w") as file:
        json.dump(dataset["findings"], file)
        logger.info(
            "Findings for requested project/repo: "
            + dataset["project"]
            + "written to: "
            + json_filepath
        )

    return json_filepath


# Generate a CSV file of findings from a JSON file of findings.
def generate_csv_report(project_name, json_filepath, out_folder):
    csv_filepath = init_out_file(out_folder, project_name, ".csv")
    logger.info(f"starting process to convert JSON file to csv for repo {project_name}")

    df = json_to_df(json_filepath)

    # This is redundant not sure why it is here
    # df = df.rename(columns={'rule_name' : 'Finding Title' , 'rule_message'  : 'Finding Description & Remediation', 'relevant_since' : 'First Seen'})

    # Write the DataFrame to CSV
    df.to_csv(csv_filepath, index=False)

    logger.info(
        "Findings converted from JSON file : "
        + json_filepath
        + " to CSV File: "
        + csv_filepath
    )

    return csv_filepath


# Generate an HTML report from a JSON file of findings.
def generate_html_report(project_name, json_filepath, out_folder):
    html_filepath = init_out_file(out_folder, project_name, ".html")
    logger.info(
        f"starting process to convert JSON file to HTML for repo {project_name}"
    )
    findings = load_findings_df(json_filepath)
    logger.debug(f"findings_count: {len(findings)}")
    # # #  create new df_high by filtering df for HIGH severity
    # df_high = df.loc[(df["severity"] == "high")]

    # # #  create new df_med by filtering df for MED severity
    logger.debug("medium findings")
    logger.debug(findings.loc[(findings["severity"] == "medium")])

    # # #  create new df_low by filtering df for LOW severity
    logger.debug("low findings")
    logger.debug(findings.loc[(findings["severity"] == "low")])

    logger.debug(findings)
    # generate the HTML from the dataframe
    html = generate_html_sast(project_name, findings)

    # write the HTML content to an HTML file
    open(html_filepath, "w").write(html)

    logger.info(
        "Findings converted from JSON file : "
        + json_filepath
        + " to HTML File: "
        + html_filepath
    )
    return html_filepath


# Generate an PDF report from an HTML report.
def generate_pdf_report(project_name, html_filepath, out_folder):
    pdf_filepath = init_out_file(out_folder, project_name, ".pdf")
    logger.info(f"starting process to convert HTML file to PDF for repo {project_name}")
    # result_file = open(pdf_filepath, "w+b")
    # with open(html_filepath, "r") as html_file:
    #     pisa_status = pisa.CreatePDF(html_file.read(), dest=result_file)

    # result_file.close()

    HTML(html_filepath).write_pdf(pdf_filepath)
    return pdf_filepath


# Generate an Excel worksheet from a JSON file of findings.
def generate_xlsx_report(project_name, json_filepath, out_folder):
    logger.info(
        f"starting process to convert JSON file to XLSX for repo {project_name}"
    )
    xlsx_filepath = init_out_file(out_folder, project_name, ".xlsx")

    df = load_findings_df(json_filepath)
    start_row_index = 0

    # Create an new Excel Writer
    writer = pd.ExcelWriter(xlsx_filepath, engine="xlsxwriter")

    # Write the data to the writer.
    # Turn off the default header and index and skip one row to allow insertion of user-defined header.
    df.to_excel(
        writer,
        sheet_name="findings",
        startrow=start_row_index,
        header=True,
        index=False,
    )
    # Get the xlsxwriter workbook and worksheet objects
    workbook = writer.book
    worksheet = writer.sheets["findings"]

    # Get the dimensions of the dataframe.
    (max_row, max_col) = df.shape

    # Create a list of column headers, to use in add_table().
    column_settings = [{"header": column.split(".")[-1]} for column in df.columns]

    # Add the Excel table structure. Pandas will add the data.
    # we start from row = 4 to allow us to insert a title and summary of findings
    worksheet.add_table(
        start_row_index,
        0,
        max_row + start_row_index,
        max_col - 1,
        {"columns": column_settings},
    )

    # Add a format.
    text_format = workbook.add_format({"text_wrap": True})

    # Make the text columns width = 48 & add text wrap for clarity
    worksheet.set_column(0, max_col - 1, 48, text_format)

    # Make the message columns width = 96 & add text wrap for clarity
    worksheet.set_column(1, 1, 96, text_format)

    # Make the severity, confidence, likelyhood & impact columns width = 12
    worksheet.set_column(4, 7, 12)

    tables = {"severity": ["high", "medium", "low"]}

    for property in tables:
        for value in tables[property]:
            table_data = df.loc[(df[property] == value)]
            column_settings = [
                {"header": column.split(".")[-1]} for column in table_data.columns
            ]

    writer.close()
    return xlsx_filepath


def generate_combination_report_images(datasets, out_folder):
    # combination_dataset = {"project": "All Projects", "findings": []}
    # for dataset in datasets:
    #     combination_dataset["findings"] += dataset["findings"]
    # combination_dataset = tabulate_summary_data([combination_dataset])[0]

    combo_severity_statuses = []
    combo_vuln_classes = []
    combo_owasp_categories = []
    for dataset in datasets:
        combo_severity_statuses.append({dataset["project"]: dataset["severity_status"]})
        combo_vuln_classes.append({dataset["project"]: dataset["vuln_class_counts"]})
        combo_owasp_categories.append({dataset["project"]: dataset["owasp_counts"]})

    create_bar_graph_open_vulns(combo_severity_statuses, out_folder)

    create_bar_graph_fixed_vulns(combo_severity_statuses, out_folder)

    create_heatmap_vulnerability_classes(combo_vuln_classes, out_folder)

    create_heatmap_owasp_top10_categories(combo_vuln_classes, out_folder)
    return [
        {
            "title": "Top 15 Projects with High Severity Open Vulnerability Count",
            "id": "bar_graph_open_vulns",
            "alt": "open_vulns",
            "filepath": os.path.join(out_folder, "open.png"),
        },
        {
            "title": "Top 15 Projects with High Severity Fixed Vulnerability Count",
            "id": "bar_graph_fixed_vulns",
            "alt": "fixed_vulns",
            "filepath": os.path.join(out_folder, "fixed.png"),
        },
        {
            "title": "Vulnerability Classes for Top 15 Projects with High Severity Open Vulnerability Count",
            "id": "heatmap_vuln_classes",
            "alt": "heatmap_vuln_classes",
            "filepath": os.path.join(out_folder, "heatmap_vulnerability_classes.png"),
        },
        {
            "title": "Vulnerability Classes for Top 15 Projects with High Severity Open Vulnerability Count",
            "id": "heatmap_owasp_top10_categories",
            "alt": "heatmap_owasp_top10_categories",
            "filepath": os.path.join(out_folder, "heatmap_owasp_top10_categories.png"),
        },
    ]
