import os
import logging
from argparse import ArgumentParser
from semgrep_reporter import log
from semgrep_reporter.findings import assemble_report_data
from semgrep_reporter.report import generate_reports
from semgrep_reporter.fileutil import init_out_folder

logger = logging.getLogger(__name__)


def main():
    try:
        SEMGREP_API_WEB_TOKEN = os.environ["SEMGREP_API_WEB_TOKEN"]
    except KeyError:
        raise SystemExit("SEMGREP_API_WEB_TOKEN is not set.")
    try:
        parser = configure_args()
        args = parser.parse_args()
        log.validate_level(parser, args)
        out_folder = init_out_folder()

        if args.all:
            set_all_format_args(args, True)

        report_datasets = assemble_report_data(
            api_token=SEMGREP_API_WEB_TOKEN,
            tag=args.tag,
            aggregate=args.agg,
            important=args.important,
        )

        if len(report_datasets) == 0:
            exit_message = "No projects to report on."
            if args.tag is not None:
                exit_message = "No projects with the tag " + args.tag + " to report on."
            parser.exit(1, exit_message)

        generate_reports(
            report_datasets,
            out_folder,
            args.combine,
            args.json,
            args.html,
            args.csv,
            args.pdf,
            args.xlsx,
            tag=args.tag,
        )

    except KeyboardInterrupt:
        raise SystemExit("Terminated by user request.")

    logger.info("Completed reporting process")
    return


def configure_args():
    parser = ArgumentParser(
        prog="Semgrep Report Generator",
        description="Generates CSV, HTML, and PDF reports from your Semgrep Cloud Platform data.",
    )
    # parser.add_argument("output_file", help="The name of the report")
    parser.add_argument(
        "-t", "--tag", type=str, help="Use to report on all projects with this tag."
    )
    parser.add_argument(
        "-i",
        "--important",
        action="store_true",
        help="Report on important findings only.",
    )
    parser.add_argument(
        "--combine",
        action="store_true",
        help="Generate an additional report combining and summarizing all of the other reports.",
    )
    parser.add_argument(
        "--agg",
        action="store_true",
        help="Aggregate findings from all projects into a single report.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Set flag to create JSON files of findings."
    )
    parser.add_argument(
        "--csv", action="store_true", help="Set flag to create CSV files of findings."
    )
    parser.add_argument(
        "--html", action="store_true", help="Set flag to create HTML reports."
    )
    parser.add_argument(
        "--pdf", action="store_true", help="Set flag to create pdf reports."
    )
    parser.add_argument(
        "--xlsx", action="store_true", help="Set flag to create Excel reports."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Set flag to generate all reports and output formats.",
    )
    log.add_log_arg(parser)
    return parser


def set_all_format_args(args, value: bool):
    args.json = value
    args.html = value
    args.csv = value
    args.pdf = value
    args.xlsx = value
    return args


if __name__ == "__main__":
    main()
