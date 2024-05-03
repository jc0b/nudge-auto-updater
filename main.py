#!/usr/bin/env python3
import json
import logging
import sys

DEFAULT_DEADLINE_DAYS = 14
URGENT_DEADLINE_DAYS = 7

def get_nudge_config() -> dict:
	logging.info("Loading Nudge config...")
	try: 
		f = open("nudge-config.json")
		data = json.load(f)
	except e:
		logging.error("Unable to open nudge-config.json")
		sys.exit(1)

	logging.info("Successfully loaded Nudge config!")
	return data

def get_macos_data() -> dict:
	return {"version": "14.5"}

def write_nudge_config(dict):
	pass

def main():
	nudge_config = get_nudge_config()
	latest_macos_release = get_macos_data()

	if nudge_config["osVersionRequirements"]
	# check whether the macOS feed has a macOS version
	# newer than enforced by Nudge
	# if not, exit here already

	# if yes, we can assess the CVEs to determine the relevant deadline

	write_nudge_config(nudge_config)


def setup_logging():
	logger = logging.getLogger(__name__)
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(levelname)-2s: %(asctime)s %(module)-6s: %(message)s",
		datefmt="%Y/%m/%d %H:%M:%S",
	)

if __name__ == '__main__':
	setup_logging()
	main()
