#!/usr/bin/env python3
import datetime
import json
import logging
import os
import urllib.error
import urllib.request
import sys


DEFAULT_DEADLINE_DAYS = 14
URGENT_DEADLINE_DAYS = 7
CONFIG_FILE_NAME = "configuration.yml"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


try:
	import yaml
except ModuleNotFoundError as e:
	if os.path.exists(CONFIG_FILE_NAME):
		logging.error(f"Can't read configuration file: {e}")
		sys.exit(1)
	else:
		logging.warning("PyYAML library could not be loaded, but no configuration file is present.\nWill continue with default settings.")


class Version:
	major = minor = patch = 0

	def __init__(self, a, b=0, c=0):
		# takes as input (major:int, minor:int=0, patch:int=0) or (s:str)
		if isinstance(a, int):
			self._process_version_ints(a, b, c)
		elif isinstance(a, str):
			self._process_version_str(a)
		else:
			logging.error(f"Unable to interpret Version from {a}, {b}, {c}.")
			sys.exit(1)
	
	@classmethod
	def from_str(cls, s: str):
		return cls(s)

	@classmethod
	def from_ints(cls, major, minor=0, patch=0):
		return cls(major, minor, patch)

	@classmethod
	def from_int(cls, major, minor=0, patch=0):
		return cls(major, minor, patch)

	def _process_version_ints(self, major:int, minor:int, patch:int):
		self.major = major
		self.minor = minor
		self.patch = patch

	def _process_version_str(self, s:str):
		parts = s.split(".")
		self.major = int(parts[0])
		if len(parts) > 1:
			self.minor = int(parts[1])
		if len(parts) > 2:
			self.patch = int(parts[2])

	def __str__(self):
		if self.patch == 0:
			return f"{self.major}.{self.minor}"
		return f"{self.major}.{self.minor}.{self.patch}"

	def __eq__(self, other):
		if isinstance(other, Version):
			return (self.major == other.major) and (self.minor == other.minor) and (self.patch == other.patch)
		else:
			return False

	def __ne__(self, other):
		return not self.__eq__(other)

	def __gt__(self, other):
		if isinstance(other, Version):
			if self.major == other.major:
				if self.minor == other.minor:
					if self.patch == other.patch:
						return False
					return self.patch > other.patch
				return self.minor > other.minor
			return self.major > other.major
		return False

	def __lt__(self, other):
		if isinstance(other, Version):
			if self.major == other.major:
				if self.minor == other.minor:
					if self.patch == other.patch:
						return False
					else:
						return self.patch < other.patch
				else: 
					return self.minor < other.minor
			else:
				return self.major < other.major
		else:
			return False

def get_nudge_config() -> dict:
	logging.info("Loading Nudge config...")
	try: 
		f = open("nudge-config.json")
		try:
			data = json.load(f)
		except e:
			logging.error("Unable to load nudge-config.json")
			sys.exit(1)
	except e:
		logging.error("Unable to open nudge-config.json")
		sys.exit(1)

	logging.info("Successfully loaded Nudge config!")
	return data

def read_nudge_requirements(d:dict):
	result = dict()
	for nudge_requirement in d["osVersionRequirements"]:
		target_str = "default"
		if "targetedOSVersionsRule" in nudge_requirement:
			target_str = nudge_requirement["targetedOSVersionsRule"]
		result[target_str] = {"version":Version(nudge_requirement["requiredMinimumOSVersion"]),
													"date":datetime.datetime.strptime(nudge_requirement["requiredInstallationDate"], DATE_FORMAT)}
	return result

def write_nudge_config(d:dict):
	pass

def get_macos_data():
	headers = {
	'accept': 'application/json',
	'User-Agent': 'nudge-auto-updater/1.0'
	}
	req = urllib.request.Request(url="https://sofa.macadmins.io/v1/macos_data_feed.json", headers=headers, method="GET")

	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get SOFA feed. Exiting...")
		sys.exit(1)

	data = json.loads(response.read().decode('utf-8'))
	logging.info("Successfully loaded macOS release data from SOFA!")

def get_config() -> dict:
	result = [{"target":"default", "update_to":"latest"}]
	with open(CONFIG_FILE_NAME, "r") as config_yaml:
		logging.info(f"Loading {CONFIG_FILE_NAME} ...")
		try:
			result = yaml.safe_load(config_yaml)
			logging.info(f"Successfully loaded {CONFIG_FILE_NAME}!")
		except yaml.YAMLError as e:
			logging.error(f"Unable to load {CONFIG_FILE_NAME}")
			sys.exit(1)
	return result


def main():
	nudge_config = get_nudge_config()
	latest_macos_release = get_macos_data()
	config = get_config()

	# check per configuration if it needs to be updates
	nudge_requirements = read_nudge_requirements(nudge_config)



		# nudge_requirements[nudge_requirement["targetedOSVersionsRule"]] = 
		# nudge_version = Version(nudge_requirement["requiredMinimumOSVersion"])
		# date_str = nudge_requirement["requiredInstallationDate"]
		# target_str = nudge_requirement["targetedOSVersionsRule"]
		# print (nudge_version)
	# if not, exit here already

	# if yes, we can assess the CVEs to determine the relevant deadline

	write_nudge_config(nudge_config)

	# test stuff
	



def setup_logging():
	logger = logging.getLogger(__name__)
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(levelname)-2s: %(asctime)s (%(module)s) %(message)s",
		datefmt="%Y/%m/%d %H:%M:%S",
	)

if __name__ == '__main__':
	setup_logging()
	main()
