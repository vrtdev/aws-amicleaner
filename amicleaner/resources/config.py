#!/usr/bin/env python
# -*- coding: utf-8 -*-

# set your aws env vars to production

class Terminal:
    # ANSI color codes to replace termcolor
    ANSI_COLORS = {
        'reset': '\033[0m',
        'bold': '\033[1m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
    }

    def colored(self, text, color):
        """Simple replacement for termcolor.colored function."""
        return f"{self.ANSI_COLORS.get(color, '')}{text}{self.ANSI_COLORS['reset']}"

    def __getattr__(self, color):
        """Dynamically create functions based on terminal colors."""
        return lambda text: self.colored(text, color)


# terminal colors
TERM = Terminal()

# Number of previous amis to keep based on grouping strategy
# not including the ami currently running by an ec2 instance
KEEP_PREVIOUS = 4

# the way to regroup AMIs, the default filtering pattern is the creation date
# and the possible other values are :
#
# name : with a grep into the ami name
#        ex: ubuntu => ["ubuntu-20160122", "ubuntu-20160123"]
# tags : with keys provided in GROUPING_STRATEGY_TAGS_KEYS, it filters AMI tags
#        ex: ["Role", "Env"] => ["ubuntu-20160122"]
#
MAPPING_KEY = "tags"


MAPPING_VALUES = ["environment", "role"]


EXCLUDED_MAPPING_VALUES = []


# Number of days amis to keep based on creation date and grouping strategy
# not including the ami currently running by an ec2 instance
AMI_MIN_DAYS = -1

BOTO3_RETRIES = 10

# Default AWS region_name
REGION_NAME = "eu-west-1"
