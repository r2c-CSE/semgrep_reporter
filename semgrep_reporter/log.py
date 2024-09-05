import logging

LOG_LEVELS = {
    "ALL": logging.NOTSET,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

logging.basicConfig(level=LOG_LEVELS["INFO"])
logger = logging.getLogger("semgrepreporter")


def add_log_arg(parser):
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=LOG_LEVELS,
        help="Set the level of logging during report generation. Options include DEBUG, INFO, WARNING, ERROR, or choose ALL for all levels of logging.",
    )


def validate_level(parser, args):
    if args.loglevel:
        if args.loglevel.upper() not in LOG_LEVELS:
            parser.error("Invalid Log Level: " + args.loglevel)
            return
        logger.setLevel(LOG_LEVELS[args.loglevel])
