import os
import logging
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.offline import plot
from dominate.tags import div, img, h2

logger = logging.getLogger(__name__)


@div
def report_image(image_header, image_id, alt_text, image_filepath):
    div(
        h2(
            image_header,
            id=image_id,
        ),
        cls="heading",
    )
    div(cls="spacer")
    div(img(src=image_filepath, alt="open_vulns", id="myImage"))
    div(cls="break-always")


# TODO: make it so this logo is local. Sometimes this site is down.
def semgrep_logo():
    return div(
        img(src="https://i.ibb.co/8xyV6WJ/Semgrep-logo.png", alt="logo", id="myImage"),
        cls="container",
    )


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


def create_heatmap_vulnerability_classes(vulnerability_counts_all_repos, image_folder):

    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame(
        {list(d.keys())[0]: list(d.values())[0] for d in vulnerability_counts_all_repos}
    ).T.fillna(0)

    # Calculate the total number of vulnerabilities for each repository
    df["Total"] = df.sum(axis=1)

    # Sort repositories by total vulnerabilities in decreasing order and select the top 15
    df_sorted = df.sort_values(by="Total", ascending=False).head(15)

    # Drop the 'Total' column as it's no longer needed in the heatmap
    df_sorted = df_sorted.drop(columns=["Total"])

    # Custom Red-Amber-Green color scale
    rag_colorscale = [
        [0.0, "green"],
        [0.10, "green"],
        [0.10, "yellow"],
        [0.33, "yellow"],
        [0.33, "red"],
        [1.0, "red"],
    ]

    # Generate the heatmap
    fig = go.Figure(
        data=go.Heatmap(
            z=df_sorted.values,
            x=df_sorted.columns,
            y=df_sorted.index,
            colorscale=rag_colorscale,
            text=df_sorted.values.astype(int).astype(
                str
            ),  # Convert the values to strings for display
            texttemplate="%{text}",
            hoverinfo="text",
        )
    )

    # Set the title and axis labels, and adjust the size of the heatmap image
    fig.update_layout(
        xaxis_title="Vulnerability Class",
        yaxis_title="Repository",
        xaxis=dict(side="top"),
        width=1200,  # Adjust the width as needed
        height=800,  # Adjust the height based on the number of repos to display
    )

    # Save the figure as an image file
    fig.write_image(f"{image_folder}/heatmap_vulnerability_classes.png")


def create_heatmap_owasp_top10_categories(owasp_top10_counts_all_repos, image_folder):

    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame(
        {list(d.keys())[0]: list(d.values())[0] for d in owasp_top10_counts_all_repos}
    ).T.fillna(0)

    # Calculate the total number of vulnerabilities for each repository
    df["Total"] = df.sum(axis=1)

    # Sort repositories by total vulnerabilities in decreasing order and select the top 15
    df_sorted = df.sort_values(by="Total", ascending=False).head(15)

    # Drop the 'Total' column as it's no longer needed in the heatmap
    df_sorted = df_sorted.drop(columns=["Total"])

    # Custom Red-Amber-Green color scale
    rag_colorscale = [
        [0.0, "green"],
        [0.10, "green"],
        [0.10, "yellow"],
        [0.33, "yellow"],
        [0.33, "red"],
        [1.0, "red"],
    ]

    # Generate the heatmap
    fig = go.Figure(
        data=go.Heatmap(
            z=df_sorted.values,
            x=df_sorted.columns,
            y=df_sorted.index,
            colorscale=rag_colorscale,
            text=df_sorted.values.astype(int).astype(
                str
            ),  # Convert the values to strings for display
            texttemplate="%{text}",
            hoverinfo="text",
        )
    )

    # Set the title and axis labels, and adjust the size of the heatmap image
    fig.update_layout(
        xaxis_title="OWASP Top 10",
        yaxis_title="Repository",
        xaxis=dict(side="top"),
        width=1200,  # Adjust the width as needed
        height=800,  # Adjust the height based on the number of repos to display
    )

    # Save the figure as an image file
    fig.write_image(f"{image_folder}/heatmap_owasp_top10_categories.png")


def create_bar_graph_open_vulns(data, image_folder):
    rows = []
    for entry in data:
        for project_name, severities in entry.items():
            row = {}
            row["Project"] = project_name
            for severity, statuses in severities.items():
                if severity == "high":
                    row["high"] = (
                        statuses["open"] + statuses["reviewing"] + statuses["fixing"]
                    )
                if severity == "medium":
                    row["medium"] = (
                        statuses["open"] + statuses["reviewing"] + statuses["fixing"]
                    )
                if severity == "low":
                    row["low"] = (
                        statuses["open"] + statuses["reviewing"] + statuses["fixing"]
                    )
            print(row)
            rows.append(row)

    transformed_json = {
        "Project": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    logger.debug(f"rows is {rows}")
    # Populate the new structure
    for item in rows:
        for key in transformed_json:
            logger.debug(f"item is {item}")
            logger.debug(f"key is {key}")
            logger.debug(f"item[key] is {item[key]}")
            transformed_json[key].append(item[key])

    logger.debug(transformed_json)

    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    logger.debug(df)

    # Sorting the DataFrame by 'Subcolumn1' in descending order and selecting the top 10
    df = df.sort_values(by="high", ascending=False).head(15)

    # Melting the DataFrame to long format, which Plotly can use to differentiate subcolumns
    df_long = pd.melt(
        df,
        id_vars="Project",
        value_vars=["high", "medium", "low"],
        var_name="Severity",
        value_name="Value",
    )

    # Adding a column for text to display the value on all bars
    df_long["Text"] = df_long["Value"].apply(lambda x: f"{x}")

    color_map = {
        "high": "darkred",  # Dark Red
        "medium": "darkorange",  # Dark Orange
        "low": "darkgoldenrod",  # Dark Yellow
    }

    # Create a bar graph with subcolumns for the top 10 objects
    fig = px.bar(
        df_long,
        x="Project",
        y="Value",
        color="Severity",
        barmode="group",
        color_discrete_map=color_map,
        text="Text",
        title="Top 15 Repos by High Severity Open Vulnerabilities count",
    )

    fig.update_traces(texttemplate="%{text}", textposition="outside")

    # Update the layout for axis titles
    fig.update_layout(
        xaxis_title="Project Name", yaxis_title="Number of Vulnerabilities"
    )

    graph_div = plot(fig, output_type="div", include_plotlyjs=False)

    # Show the plot
    # fig.show()
    fig.write_image(f"{image_folder}/open.png")
    return graph_div


def create_bar_graph_fixed_vulns(data, image_folder):
    rows = []
    for entry in data:
        for project_name, severities in entry.items():
            row = {}
            row["Project"] = project_name
            for severity, statuses in severities.items():
                if severity == "high":
                    row["high"] = statuses["fixed"]
                if severity == "medium":
                    row["medium"] = statuses["fixed"]
                if severity == "low":
                    row["low"] = statuses["fixed"]
            print(row)
            rows.append(row)

    transformed_json = {
        "Project": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    logger.debug(f"rows is {rows}")
    # Populate the new structure
    for item in rows:
        for key in transformed_json:
            logger.debug(f"item is {item}")
            logger.debug(f"key is {key}")
            logger.debug(f"item[key] is {item[key]}")
            transformed_json[key].append(item[key])

    logger.debug(transformed_json)

    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    logger.debug(df)

    # Sorting the DataFrame by 'high' in descending order and selecting the top 10
    df = df.sort_values(by="high", ascending=False).head(15)

    # Melting the DataFrame to long format, which Plotly can use to differentiate subcolumns
    df_long = pd.melt(
        df,
        id_vars="Project",
        value_vars=["high", "medium", "low"],
        var_name="Severity",
        value_name="Value",
    )

    # Adding a column for text to display the value on all bars
    df_long["Text"] = df_long["Value"].apply(lambda x: f"{x}")

    color_map = {
        "high": "darkred",  # Dark Red
        "medium": "darkorange",  # Dark Orange
        "low": "darkgoldenrod",  # Dark Yellow
    }

    # Create a bar graph with subcolumns for the top 10 objects
    fig = px.bar(
        df_long,
        x="Project",
        y="Value",
        color="Severity",
        barmode="group",
        color_discrete_map=color_map,
        text="Text",
        title="Top 15 Repos by High Severity Fixed Vulnerabilities count",
    )

    fig.update_traces(texttemplate="%{text}", textposition="outside")

    # Update the layout for axis titles
    fig.update_layout(
        xaxis_title="Project Name", yaxis_title="Number of Vulnerabilities"
    )

    graph_div = plot(fig, output_type="div", include_plotlyjs=False)

    # Show the plot
    # fig.show()
    fig.write_image(f"{image_folder}/fixed.png")

    return graph_div
