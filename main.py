#!/usr/bin/env python3
import datetime
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request

CONFIG_FILE_NAME = "configuration.yml"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
HEADERS = {'accept': 'application/json', 'User-Agent': 'nudge-auto-updater/1.0'}

try:
	api_key = os.environ["NVD_API_KEY"]
	HEADERS["apiKey"] = api_key
	logging.info("Using the provided NVD API key...")
except KeyError as e:
	logging.warning(f"The {e} environment variable is not set. You will be rate-limited by the NIST NVD API.")
	

try:
	import yaml
except ModuleNotFoundError as e:
	if os.path.exists(CONFIG_FILE_NAME):
		logging.error(f"Can't read configuration file: {e}")
		sys.exit(1)
	else:
		logging.warning("PyYAML library could not be loaded, but no configuration file is present.\nWill continue with default settings.")

# ----------------------------------------
# 								Version
# ----------------------------------------
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

# ----------------------------------------
# 								Nudge
# ----------------------------------------
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

# ----------------------------------------
# 								macOS
# ----------------------------------------
def get_macos_data():
	req = urllib.request.Request(url="https://sofa.macadmins.io/v1/macos_data_feed.json", headers=HEADERS, method="GET")
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
	releases = []
	cves = {}
	for release in d["OSVersions"]:
		version = Version(release["Latest"]["ProductVersion"])
		releases.append(version)
		found_security_release = False
		for security_release in release["SecurityReleases"]:
			if security_release["ProductVersion"] == release["Latest"]["ProductVersion"]:
				if "CVEs" in security_release:
					security_release_cves = security_release["CVEs"]
					for cve in security_release_cves:
						security_release_cves[cve] = get_CVE_info(cve, security_release_cves[cve])
					cves[str(version)] = security_release_cves
				else:
					cves[str(version)] = dict()
				found_security_release = True
				break
		if not found_security_release:
			logging.error(f"Unable to find security release for macOS {version}")
			sys.exit(1)
	return releases, cves

def get_CVE_info(s:str, b:bool):
	req = urllib.request.Request(url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={s}", headers=HEADERS, method="GET")
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get CVE data for {s}.")
		sys.exit(1)
	try:
		result = json.loads(response.read().decode('utf-8'))
	except Error as e:
		logging.error(f"Unable to load CVE data for {s}.")
		sys.exit(1)
	return read_CVE_info(result["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0], b)

def read_CVE_info(d:dict, b:bool):
	print(d)
	result = dict()
	result["baseScore"] = d["cvssData"]["baseScore"]
	result["exploitabilityScore"] = d["exploitabilityScore"]
	result["impactScore"] = d["impactScore"]
	result["is_actively_exploited"] = int(b)
	return result

# ----------------------------------------
# 					  	Configurations
# ----------------------------------------
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

def get_gt_config_target(s:str):
	config_version_parts = s.split(".")
	if len(config_version_parts) == 1 :
		return Version(int(config_version_parts[0]) + 1)
	elif len(parts) == 2:
		return Version(int(config_version_parts[0]), int(config_version_parts[1]) + 1)
	elif len(parts) == 3:
		return Version(int(config_version_parts[0]), int(config_version_parts[1]), int(config_version_parts[2]) + 1)
	logging.error(f"{s} is not a valid target in configuration.yml")
	sys.exit(1)

def read_formula(formula_str:str, cve_name:str, cve:dict):
	formula_str = formula_str.replace(" ", "")
	formula_str = formula_str.lower()
	for key in cve:
		formula_str = formula_str.replace(key.lower(), str(cve[key]))
	formula_str_old = ""
	try:
		while formula_str != formula_str_old:
			formula_str_old = formula_str
			temp_str = ""
			while formula_str != temp_str:
				temp_str = formula_str
				formula_str = re.sub(r"[0-9]+(\.[0-9]+)?\^[0-9]+(\.[0-9]+)?", exp_subformula, formula_str_old)
			temp_str = ""
			while formula_str != temp_str:
				temp_str = formula_str
				formula_str = re.sub(r"[0-9]+(\.[0-9]+)?/[0-9]+(\.[0-9]+)?", div_subformula, formula_str)
			temp_str = ""
			while formula_str != temp_str:
				temp_str = formula_str
				formula_str = re.sub(r"[0-9]+(\.[0-9]+)?\*[0-9]+(\.[0-9]+)?", mul_subformula, formula_str)
			temp_str = ""
			while formula_str != temp_str:
				temp_str = formula_str
				formula_str = re.sub(r"[0-9]+(\.[0-9]+)?\+[0-9]+(\.[0-9]+)?", add_subformula, formula_str)
			temp_str = ""
			while formula_str != temp_str:
				temp_str = formula_str
				formula_str = re.sub(r"[0-9]+(\.[0-9]+)?-[0-9]+(\.[0-9]+)?", sub_subformula, formula_str)
		return float(formula_str)
	except Error as e:
		logging.error(f"Unable to interpret cve_urgency_conditions formula {s} for CVE {cve_name}.")
		sys.exit(1)

def split_subformula(match):
	s = match[0]
	l = re.split(r"\^|/|\*|\+|-", s)
	if len(l) == 2:
		return float(l[0]), float(l[1])
	else:
		raise Exception(f"Unable to interpret {s} in cve_urgency_conditions formula.")

def exp_subformula(match):
	a, b = split_subformula(match)
	result = a ^ b
	return str(result)

def div_subformula(match):
	a, b = split_subformula(match)
	result = a / b
	return str(result)

def mul_subformula(match):
	a, b = split_subformula(match)
	result = a * b
	return str(result)

def sub_subformula(match):
	a, b = split_subformula(match)
	result = a - b
	return str(result)

def add_subformula(match):
	a, b = split_subformula(match)
	result = a + b
	return str(result)

def brackets_subformula(match):
	return match[0][1:-1]


# ----------------------------------------
# 				  Check CVE Conditions
# ----------------------------------------
def is_deadline_urgent(conditions, cves):
	if len(cves) < 1:
		return False
	for score in ["baseScore", "exploitabilityScore", "impactScore"]:
		if f"max_{score}" in conditions:
			l = []
			for cve in cves:
				l.append(cves[cve][score])
			l.sort(reverse=True)
			if l[0] > conditions[f"max_{score}"]:
				logging.info(f'CVE urgency condition met! Max {score} of {l[0]} is higher than threshhold {conditions[f"max_{score}"]}.')
				return True
		if f"average_{score}" in conditions:
			l = []
			for cve in cves:
				l.append(cves[cve][score])
			if (sum(l) / len(l)) > conditions[f"average_{score}"]:
				logging.info(f'CVE urgency condition met! Average {score} of {(sum(l) / len(l))} is higher than threshhold {conditions[f"average_{score}"]}.')
				return True
	if "number_CVEs" in conditions:
		if len(cves) < conditions["number_CVEs"]:
			logging.info(f'CVE urgency condition met! Number of CVEs ({len(cves)}) is higher than threshhold {conditions["number_CVEs"]}.')
			return True
	if "number_actively_exploited_CVEs" in conditions:
		l = []
		for cve in cves:
			l.append(cves[cve]["is_actively_exploited"])
		if sum(l) > conditions[f"number_actively_exploited_CVEs"]:
			logging.info(f'CVE urgency condition met! Number of actively exploited CVEs ({sum(l)}) is higher than threshhold {conditions["number_actively_exploited_CVEs"]}.')
			return True
	if "fraction_actively_exploited_CVEs" in conditions:
		l = []
		for cve in cves:
			l.append(cves[cve]["is_actively_exploited"])
		if (sum(l) / len(l)) > conditions["fraction_actively_exploited_CVEs"]:
			logging.info(f'CVE urgency condition met! Fracction of actively exploited CVEs ({(sum(l) / len(l))}) is higher than threshold {conditions["fraction_actively_exploited_CVEs"]}.')
			return True
	if "formulas" in conditions:
		for formula in conditions["formulas"]:
			pass



# cve_urgency_conditions:
#   max_baseScore : 10
#   average_baseSeverity : 8
#   max_exploitabilityScore : 10
#   average_exploitabilityScore : 8
#   max_impactScore : 10
#   average_impactScore : 8
#   number_CVEs : 10
#   number_actively_exploited_CVEs : 5
#   fraction_actively_exploited_CVEs : 0.7
#   formulas:
#     - comparison : "average"
#       formula : "baseScore * exploitabilityScore * impactScore"
#       threshhold : 500
#     - comparison : "max"
#       formula : "baseScore * exploitabilityScore * impactScore * is_actively_exploited"
#       threshhold : 200
#     - comparison : "sum"
#       formula    : "baseScore  * impactScore * is_actively_exploited"
#       threshhold : 300

def main():
	nudge_requirements = get_nudge_config()
	latest_macos_releases, cves = get_macos_data()
	latest_macos_releases.sort(reverse=True)
	config = get_config()

	# check per configuration if it needs to be updates
	for target in config["targets"]:
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
		# get all cves for the latest release
		# is that cve being actively exploited/
		# the severity rating of that cve
	# then we need toupdate nudge


	# test stuff
	print(cves)
	print(get_CVE_info("CVE-2024-1580"))


	
	



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
