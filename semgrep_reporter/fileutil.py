import re
import time
import os
import logging
import json
import pandas as pd
from PyPDF2 import PdfMerger
import html
from semgrep_reporter.datafields import CSV_COLUMNS, SAST_REPORT_COLUMNS
from semgrep_reporter.html import escape_html_description, generate_combined_html
from semgrep_reporter.image import generate_combination_report_images

logger = logging.getLogger(__name__)

UNIX_TIME = str(int(time.time()))


# Creates an output folder for the reports.
# The folder name is the unix timestamp of the run.
def init_out_folder():
    # create folder reports/UNIX_TIME
    output_folder = os.path.join(
        os.getcwd(), "reports", UNIX_TIME
    )  # Define the output path
    os.makedirs(output_folder, exist_ok=True)
    return output_folder


# Creates a filename for the project and file type with the path to the output folder.
def init_out_file(out_folder, report_name, ext):
    # Construct the full path for the output file
    output_file = re.sub(r"[^\w\s]", "_", report_name) + "-" + UNIX_TIME + ext
    logger.debug("%s", out_folder)
    output_filepath = os.path.join(out_folder, output_file)
    return output_filepath


# Read a JSON file of findings and format into a dataframe for CSV reporting.
def json_to_df(json_file):
    # Read the JSON file into a DataFrame
    df = pd.read_json(json_file)

    if df.empty:
        # No findings so return an empty dataframe with relevant headers.
        return pd.DataFrame(columns=CSV_COLUMNS)

    # Rename properties to be prettier
    df = df.rename(
        columns={
            "rule_name": "Finding Title",
            "rule_message": "Finding Description & Remediation",
            "relevant_since": "First Seen",
        }
    )
    # Filter out specific columns
    df = df.loc[
        :,
        CSV_COLUMNS,
    ]
    logging.info("Findings converted to DF from JSON file : " + json_file)

    return df


# Load a JSON file of findings into a dataframe for HTML, PDF, and XLSX reporting.
def load_findings_df(json_filepath):
    df = json_to_normalized_df(json_filepath)

    df = df.rename(
        columns={
            "rule_name": "Finding Title",
            "rule_message": "Finding Description & Remediation",
            "relevant_since": "First Seen",
        }
    )
    # Create new DF with SAST findings only
    # df_sast = df.loc[(df['check_id'].str.contains('ssc')==False)]

    if df.empty:
        full_columns = SAST_REPORT_COLUMNS + ["short_ref", "link_to_code", "location"]
        df = pd.DataFrame(columns=full_columns)
    else:
        # Filter data by the columns of interest
        df = df[SAST_REPORT_COLUMNS]

        # Apply the function and create a new column
        df["Finding Description & Remediation"] = df.apply(
            escape_html_description, axis=1
        )
        df["Finding Title"] = df.apply(add_short_rule_name, axis=1)
        df["short_ref"] = df.apply(add_short_ref, axis=1)
        df["link_to_code"] = df.apply(add_hyperlink_to_code, axis=1)
        # df['repository'] = df.apply(add_repo_details, axis=1)
        df["location"] = df.apply(add_location_details_hyperlink, axis=1)

    df.drop(
        [
            "repository.name",
            "repository.url",
            "location.file_path",
            "location.line",
            "link_to_code",
            "short_ref",
        ],
        axis=1,
        inplace=True,
    )
    return df


# Add a short reference to the finding columns
def add_short_ref(row):
    match = re.search(r"\b\w+$", row["ref"])
    # Return the found word or None if no match
    return match.group(0) if match else None


# Add a shortened Finding Title to the finding columns
def add_short_rule_name(row):
    # Split the string by period
    items = row["Finding Title"].split(".")
    last_item = items[-1]
    link_to_rule = f"https://semgrep.dev/r?q={row['Finding Title']}"

    # return the last item
    return html.unescape("<a href='" + link_to_rule + "'>" + last_item + "</a>")


# Add a hyperlink to the finding in code.
def add_hyperlink_to_code(row):
    return (
        row["repository.url"]
        + "/blob/"
        + row["short_ref"]
        + "/"
        + row["location.file_path"]
        + "#L"
        + str(row["location.line"])
    )


# Add repo URL and Name to the table
def add_repo_details(row):
    return html.unescape(
        "<a href='" + row["repository.url"] + "'>" + row["repository.name"] + "</a>"
    )


# Add location of finding to the table
def add_location_details_hyperlink(row):
    return html.unescape(
        "<a href='"
        + row["link_to_code"]
        + "'>"
        + row["location.file_path"]
        + "#L"
        + str(row["location.line"])
        + "</a>"
    )


# Read a JSON file of findings and normalize for HTML/PDF/XLSX reporting.
def json_to_normalized_df(json_file):
    with open(json_file) as json_file_data:
        data = json.load(json_file_data)

    df = pd.json_normalize(data)
    return df


# Create a new JSON report by combining all JSON files in the out_folder
def combine_json_files(out_folder, tag=None):
    filename = "combined"
    if tag is not None:
        filename += "_" + tag
    combined_json_filepath = init_out_file(out_folder, filename, ".json")
    combined_data = []

    # Loop through each file in the folder
    for filename in os.listdir(out_folder):
        if filename.endswith("-" + UNIX_TIME + ".json"):
            print("Opening " + filename)
            with open(os.path.join(out_folder, filename), "r") as file:
                data = json.load(file)

                # Append data from current file to combined data
                if isinstance(data, list):
                    combined_data.extend(data)
                else:
                    combined_data.append(data)

    # Write combined data to output file
    with open(combined_json_filepath, "w") as outfile:
        json.dump(combined_data, outfile, indent=4)
    return combined_json_filepath


# Create a new PDF report by combining all of the PDFs in the out_folder
def combine_pdf_files(out_folder, tag=None):
    filename = "combined_output"
    if tag is not None:
        filename += "_" + tag
    combined_pdf_filepath = init_out_file(out_folder, filename, ".pdf")
    # Create a PDF merger object
    merger = PdfMerger()

    # Loop through all the files in the folder
    for item in os.listdir(out_folder):
        # Check if the file is a PDF to be combined
        if item.endswith(UNIX_TIME + ".pdf"):
            # Append the PDF to the merger
            logging.debug(f"appending PDF file: {item}")
            with open(os.path.join(out_folder, item), "rb") as f:
                merger.append(f)

    # Write out the combined PDF to the output file
    with open(combined_pdf_filepath, "wb") as f_out:
        merger.write(f_out)
    merger.close()
    return combined_pdf_filepath


def combine_html_files(
    datasets,
    out_folder,
    tag,
):
    filename = "combined_output"
    if tag is not None:
        filename += "_" + tag
    combined_html_filepath = init_out_file(out_folder, filename, ".html")

    project_name = "All Repositories"
    if tag is not None:
        project_name += " with Tag " + tag.capitalize()

    report_images = generate_combination_report_images(datasets, out_folder)

    combined_html = generate_combined_html(
        datasets, project_name, report_images, out_folder
    )

    open(combined_html_filepath, "w").write(combined_html)
    return combined_html_filepath
