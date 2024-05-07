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
					return self.patch < other.patch
				return self.minor < other.minor
			return self.major < other.major
		return False

def get_nudge_config() -> dict:
	logging.info("Loading Nudge config...")
	try: 
		f = open("nudge-config.json")
		try:
			data = json.load(f)
		except Error as e:
			logging.error("Unable to load nudge-config.json")
			sys.exit(1)
	except Error as e:
		logging.error("Unable to open nudge-config.json")
		sys.exit(1)

	logging.info("Successfully loaded Nudge config!")
	return read_nudge_requirements(data)

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
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get SOFA feed.")
		sys.exit(1)

	try:
		result = json.loads(response.read().decode('utf-8'))
		logging.info("Successfully loaded macOS release data from SOFA!")
	except Error as e:
		logging.error("Unable to load macOS release data from SOFA.")
		sys.exit(1)
	return read_macos_data(result)

def read_macos_data(d:dict):
	result = []
	for release in d["OSVersions"]:
		version = Version(release["Latest"]["ProductVersion"])
		result.append(version)
	return result

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

def get_gt_config_target(s):
	config_version_parts = s.split(".")
	if len(config_version_parts) == 1 :
		return Version(int(config_version_parts[0]) + 1)
	elif len(parts) == 2:
		return Version(int(config_version_parts[0]), int(config_version_parts[1]) + 1)
	elif len(parts) == 3:
		return Version(int(config_version_parts[0]), int(config_version_parts[1]), int(config_version_parts[2]) + 1)
	logging.error(f"{s} is not a valid target in configuration.yml")
	sys.exit(1)

def main():
	nudge_requirements = get_nudge_config()
	latest_macos_releases = get_macos_data()
	get_macos_data().sort(reverse=True)
	print(latest_macos_releases)
	config = get_config()

	# check per configuration if it needs to be updates
	for target in config:
		if target["target"] in nudge_requirements:
			# nudge requirement needs to be checked
			if target["update_to"] == "latest":
				# nudge requirement needs to be checked against latest macOS
				if nudge_requirements[target["target"]]["version"] < latest_macos_releases[0]:
					logging.info(f"Nudge is old (nudge={nudge_requirements[target['target']]['version']}, newest={latest_macos_releases[0]})")
				else:
					logging.info(f"Nudge configuration for target {target['target']} is already up to date.")
			else:
				# nudge requirement needs to be checked against latest macOS that is up to config macOS
				config_version_gt = get_gt_config_target(target["update_to"])
				is_uptodate = True
				for macos_release in latest_macos_releases:
					if macos_release < config_version_gt and macos_release > nudge_requirements[target["target"]]["version"]:
						logging.info(f"Nudge is old (nudge={nudge_requirements[target['target']]['version']}, newest={macos_release})")
						is_uptodate = False
				if is_uptodate:
					logging.info(f"Nudge configuration for target {target['target']} is already up to date.")


	# if nudge needs to be updated, ther we can assess the CVEs to determine the relevant deadline
	# then we need toupdate nudge


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
