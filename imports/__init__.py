# __init__.py

""" Imports for the binarycookies package. """

import argparse
import pathlib
import sys
import json
import struct
from io import BytesIO
from time import strftime, gmtime
from typing import Union, BinaryIO

# Additional imports for logging, progress, and formatting
from colorama import Fore, Style
from collections import Counter
import logging
from tabulate import tabulate
import colorlog


def setup_logging():
    """
    Sets up the logging configuration for the 'binarycookies_logger' logger.

    This function creates a `StreamHandler` for the logger and sets the formatter to a `ColoredFormatter`
    with a specific log format and log colors. The logger is then set to the 'binarycookies_logger'
    logger and the log level is set to `logging.DEBUG`. The handler is added to the logger and the
    logger is returned.

    Returns:
        logging.Logger: The 'binarycookies_logger' logger.
    """
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)s:%(name)s: %(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    ))
    
    logger = colorlog.getLogger('binarycookies_logger')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger

# Initialize logger
logger = setup_logging()
