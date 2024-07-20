#!/usr/bin/env python3
import datetime
import json
import logging
import optparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

CISA_DATE_FORMAT = "%Y-%m-%d"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CONFIG_FILE_NAME = "configuration.yml"
DEFAULT_NUDGE_FILENAME = "nudge-config.json"
DEFAULT_SOFA_FEED = "https://sofa.macadmins.io/v1/macos_data_feed.json"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

HEADERS = {'accept': 'application/json', 'User-Agent': 'nudge-auto-updater/1.0'}
DEFAULT_CONFIG = {
	"targets" : [{"target": "default", "update_to": "latest"}],
	"cve_urgency_levels": [{"cve_urgency_conditions": { "fraction_actively_exploited_CVEs": 0.75 }, "deadline_days": 7, "name": "urgent"}],
	"default_deadline_days" : 14,
}
_BOOLMAP = {
	'y': True,
	'yes': True,
	't': True,
	'true': True,
	'on': True,
	'1': True,
	'n': False,
	'no': False,
	'f': False,
	'false': False,
	'off': False,
	'0': False
}

# ----------------------------------------
#                 Version
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
#               Slack
# ----------------------------------------
def send_slack_webhook(slack_url, slack_blocks):
	context_block = {"type": "context", "elements": [{"type": "mrkdwn", "text": "This message brought to you by <https://github.com/jc0b/nudge-auto-updater|nudge-auto-updater>"}]}
	context_block = slack_blocks.append(context_block)
	slack_dict = {"blocks" : slack_blocks}
	data = json.dumps(slack_dict).encode('utf-8') #data should be in bytes
	headers = {'Content-Type': 'application/json'}
	req = urllib.request.Request(slack_url, data, headers)
	resp = urllib.request.urlopen(req, context=ssl.create_default_context(cafile=certifi.where()))
	response = resp.read()
	if(resp.status == 200):
		logging.info("Slack wbhook sent successfully!")
	else:
		logging.error(f"Slack webhook could not be sent. HTTP response {resp.status}.")
		sys.exit(1)

def build_slack_block_dict(urgency_condition_met, target_description, urgency_level_description, met_cve_conditions):
	target_element  = {"type": "text", "text": target_description, "style": {"bold": True}}
	urgency_element = {"type": "text", "text": f"\n{urgency_level_description}\n"}
	header_element  = {"type": "rich_text_section", "elements": [target_element, urgency_element]}
	if urgency_condition_met:
		cve_condition_elements = []
		for met_cve_condition in met_cve_conditions:
			cve_condition_elements.append({"type": "rich_text_section", "elements": [{"type": "text", "text": met_cve_condition}]})
		list_element = {"type": "rich_text_list", "style": "bullet", "indent": 0, "border": 0, "elements": cve_condition_elements}
		return {"type": "rich_text", "elements": [header_element, list_element]}
	return {"type": "rich_text", "elements": [header_element]}

def add_to_slack_block(blocks, urgency_condition_met, target_description, urgency_level_description, met_cve_conditions):
	blocks.append(build_slack_block_dict(urgency_condition_met, target_description, urgency_level_description, met_cve_conditions))
	blocks.append({"type": "divider"})
	return blocks

def setup_slack_blocks():
	try:
		global certifi
		import certifi
	except ImportError as e:
			loggig.error(f"Certifi library could not be loaded.")
			logging.error("You can install the necessary dependencies with 'python3 -m pip install -r requirements.txt'")
			sys.exit(1)
	header_block = {"type": "header", "text": {"type": "plain_text", "text": "Nudge Configuration Updated", "emoji": True}}
	div_block = {"type": "divider"}
	return [header_block, div_block]

# ----------------------------------------
#					Markdown change log
# ----------------------------------------
def write_md_file(md_file, md):
	try:
		f = open(md_file, "w")
		f.write(md)
		f.close()
		logging.info("Markdown file successfully updated.")
	except Exception as e:
		logging.error(f"Unable to write to {md_file}")
		sys.exit(1)


def md_description(urgency_condition_met, target_description, urgency_level_description, met_cve_conditions):
	result = target_description + "\n" + urgency_level_description + "\n"
	if urgency_condition_met:
		for met_cve_condition in met_cve_conditions:
			result += "- " + met_cve_condition + "\n"
	result += "\n"
	return result

# ----------------------------------------
#                 Nudge
# ----------------------------------------
def get_nudge_config(nudge_file_name) -> dict:
	logging.info("Loading Nudge config...")
	try: 
		f = open(nudge_file_name)
		try:
			data = json.load(f)
		except Exception as e:
			logging.error(f"Unable to load {nudge_file_name}")
			sys.exit(1)
	except Exception as e:
		logging.error(f"Unable to open {nudge_file_name}")
		sys.exit(1)

	logging.info("Successfully loaded Nudge config!")
	return data, read_nudge_requirements(data)

def read_nudge_requirements(d:dict):
	result = dict()
	for nudge_requirement in d["osVersionRequirements"]:
		target_str = "default"
		if "targetedOSVersionsRule" in nudge_requirement:
			target_str = nudge_requirement["targetedOSVersionsRule"]
		result[target_str] = {"version":Version(nudge_requirement["requiredMinimumOSVersion"])}
	return result

def write_nudge_config(nudge_file_name:str, d:dict):
	try:
		with open(nudge_file_name, 'w') as f:
			json.dump(d, f, indent=4)
	except Exception as e:
		logging.error(f"Unable to write to {nudge_file_name}")
		sys.exit(1)

def update_nudge_file_dict(d:dict, target, version, url, release_date, days):
	for i, requirement in enumerate(d["osVersionRequirements"]):
		if requirement["targetedOSVersionsRule"] == target:
			d["osVersionRequirements"][i]["aboutUpdateURL_disabled"] = adjust_url(requirement["aboutUpdateURL_disabled"], url)
			for j in range(len(d["osVersionRequirements"][i]["aboutUpdateURLs"])):
				d["osVersionRequirements"][i]["aboutUpdateURLs"][j]["aboutUpdateURL"] = adjust_url(requirement["aboutUpdateURLs"][j]["aboutUpdateURL"], url)
			d["osVersionRequirements"][i]["requiredInstallationDate"] = adjust_date_str(requirement["requiredInstallationDate"], release_date, days)
			d["osVersionRequirements"][i]["requiredMinimumOSVersion"] = str(version)
			return d
	logging.error(f"Unable to find target {target} in {nudge_filename}.")
	sys.exit(1)

def adjust_url(url, change):
	i = url.rfind("/") + 1
	url = url[:i]
	url += change
	return url

def adjust_date_str(datestr, release_date, days):
	nudge_date = datetime.datetime.strptime(datestr, DATE_FORMAT)
	release_date = datetime.datetime.strptime(release_date, DATE_FORMAT)
	new_date = release_date + datetime.timedelta(days=days)
	new_date = nudge_date.replace(year=new_date.year, month=new_date.month, day=new_date.day)
	return new_date.strftime(DATE_FORMAT)

# ----------------------------------------
#                 macOS
# ----------------------------------------
def get_macos_data(sofa_url):
	req = urllib.request.Request(url=sofa_url, headers=HEADERS, method="GET")
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get SOFA feed.")
		sys.exit(1)
	try:
		result = json.loads(response.read().decode('utf-8'))
		logging.info("Successfully loaded macOS release data from SOFA!")
	except Exception as e:
		logging.error("Unable to load macOS release data from SOFA.")
		sys.exit(1)
	return read_macos_data(result)

def read_macos_data(d:dict):
	releases = []
	cves = {}
	urls = {}
	dates = {}
	for release in d["OSVersions"]:
		version = Version(release["Latest"]["ProductVersion"])
		releases.append(version)
		dates[str(version)] = release["Latest"]["ReleaseDate"]
		found_security_release = False
		for security_release in release["SecurityReleases"]:
			if security_release["ProductVersion"] == release["Latest"]["ProductVersion"]:
				urls[str(version)] = process_url(security_release["SecurityInfo"])
				if "CVEs" in security_release:
					cves[str(version)] = security_release["CVEs"]
				else:
					cves[str(version)] = dict()
				found_security_release = True
				break
		if not found_security_release:
			logging.error(f"Unable to find security release for macOS {version}")
			sys.exit(1)
	return releases, cves, urls, dates

def process_url(s:str):
	parts = s.split("/")
	return parts[-1]

def get_CVE_scores(s:str, b:bool, api_key):
	vulncheck_headers = HEADERS
	vulncheck_headers["Authorization"] = f"Bearer {api_key}"
	req = urllib.request.Request(url=f"https://api.vulncheck.com/v3/index/nist-nvd2?cve={s}", headers=HEADERS, method="GET")
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get CVE data for {s}.")
		sys.exit(1)
	try:
		result = json.loads(response.read().decode('utf-8'))
	except Exception as e:
		logging.error(f"Unable to load CVE data for {s}.")
		sys.exit(1)
	if "cvssMetricV31" in result["data"][0]["metrics"]:
		return read_CVE_scores(result["data"][0]["metrics"]["cvssMetricV31"][0], b)
	else:
		return None

def read_CVE_scores(d:dict, b:bool):
	result = dict()
	result["baseScore"] = d["cvssData"]["baseScore"]
	result["exploitabilityScore"] = d["exploitabilityScore"]
	result["impactScore"] = d["impactScore"]
	result["is_actively_exploited"] = int(b)
	return result

def check_if_cve_scores_needed(config, api_key):
	if "cve_urgency_levels" in config:
		for cve_urgency_level in config["cve_urgency_levels"]:
			if is_CVE_score_condition(cve_urgency_level["cve_urgency_conditions"]):
				# CVE scores needed for some level so need api key
				if api_key:
					return True
				logging.error(f"A VulnCheck API key is required to use this script, as CVE scores are used in the configuration. Please set it using either the VULNCHECK_API_KEY environment variable, or the --api-key argument.\n\tSee https://docs.vulncheck.com/getting-started/api-tokens for more.")
				sys.exit(1)
	return False

# ----------------------------------------
#               Configurations
# ----------------------------------------
def get_config(config_file_name, is_config_specified) -> dict:
	try:
		global yaml
		import yaml
		if not os.path.exists(config_file_name):
			# import success BUT no file 
			if is_config_specified:
				# file was user provided -> error: user provided file should exist
				logging.error(f"Configuration file {config_file_name} is not present.")
				sys.exit(1)
			else:
				# file was not user provided -> warning: use defauls
				logging.warning("No configuration file is present. Will continue with default settings.")
				return DEFAULT_CONFIG
		# import success AND file exists
		with open(config_file_name, "r") as config_yaml:
			logging.info(f"Loading {config_file_name} ...")
			try:
				result = yaml.safe_load(config_yaml)
				logging.info(f"Successfully loaded {config_file_name}!")
				return result
			except yaml.YAMLError as e:
				logging.error(f"Unable to load {config_file_name}: {e}")
				sys.exit(1)
	except ModuleNotFoundError as e:
		# import unsuccessful
		if os.path.exists(config_file_name):
			# import unsuccessful AND file exists -> error: should be able to read file
			logging.error(f"Missing dependency to read configuration file: {e}")
			sys.exit(1)
		elif is_config_specified:
			# import unsuccessful AND no file BUT file was user provided -> error: user provided file should be readable
			logging.error(f"Missing dependency to read configuration file: {e}")
			logging.error(f"Configuration file {config_file_name} is not present.")
			sys.exit(1)
		else:
			# import unsuccessful But no file -> warning: use defaults
			logging.warning("PyYAML library could not be loaded, but no configuration file is present. Will continue with default settings.")
			return DEFAULT_CONFIG

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
	except Exception as e:
		logging.error(f"Unable to interpret cve_urgency_conditions formula {s} for {cve_name}.")
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
#           Check CVE Conditions
# ----------------------------------------
def check_deadline_urgent(conditions, cves_scores, cves, name, days, conjunction=False):
	if len(conditions) < 1:
		return False, "", []
	result1, met_cve_conditions1 = check_cve_scores(conditions, cves_scores, name, days, conjunction)
	result2, met_cve_conditions2 = check_cve_numbers(conditions, cves, name, days, conjunction, result1)
	s = f'CVE urgency is "{name}"! Installation will be required {days} day(s) after release.'
	if conjunction:
		result = result1 and result2
	else:
		result = result1 or result2
	if result:
		logging.info(s)
		for met_cve_condition in met_cve_conditions1 + met_cve_conditions2:
			logging.info(met_cve_condition)
		return result, s, met_cve_conditions1 + met_cve_conditions2
	return result, "", met_cve_conditions1 + met_cve_conditions2

def check_cve_scores(conditions, cves, name, days, conjunction, found=False):
	conj = True
	disj = False
	# behaviour if no cve data
	met_cve_conditions = []
	if len(cves) < 1:
		if conjunction:
			# conjunction -> return false if looking for at least one condition, otherwise return true
			return (not is_CVE_score_condition(conditions)), []
		else:
			# disjunction -> return false
			return False, []
		return False, []
	# behaviour if at least one cve data found
	for score in ["baseScore", "exploitabilityScore", "impactScore"]:
		if f"max_{score}" in conditions:
			l = []
			d = dict()
			for cve in cves:
				l.append(cves[cve][score])
				if cves[cve][score] in d:
					d[cves[cve][score]].append(cve)
				else:
					d[cves[cve][score]] = [cve]
			l.sort(reverse=True)
			if l[0] >= conditions[f"max_{score}"]:
				condition_cve = d[l[0]][0]
				s = f'Max {score} of {l[0]} ({condition_cve}) is greater than or equal to threshold {conditions[f"max_{score}"]}.'
				met_cve_conditions.append(s)
				disj = True
			else:
				conj = False
		if f"average_{score}" in conditions:
			l = []
			for cve in cves:
				l.append(cves[cve][score])
			if (sum(l) / len(l)) >= conditions[f"average_{score}"]:
				s = f'Average {score} of {(sum(l) / len(l))} is greater or equal to than threshold {conditions[f"average_{score}"]}.'
				met_cve_conditions.append(s)
				disj = True
			else:
				conj = False
	if "formulas" in conditions:
		for formula in conditions["formulas"]:
			is_condition_met, s = check_formula_condition(formula, cves)
			if is_condition_met:
				met_cve_conditions.append(s)
				disj = True
			else:
				conj = False
	if "match_n_CVEs_conditions" in conditions:
		for i, match_n_CVEs_condition in enumerate(conditions["match_n_CVEs_conditions"]):
			is_condition_met, s = check_match_n_CVEs_condition(match_n_CVEs_condition, cves)
			if is_condition_met:
				if len(conditions["match_n_CVEs_conditions"]) == 1:
					s = f'At least {conditions["match_n_CVEs_conditions"][i]["n"]} CVE(s) met the specified "match n CVEs condition" ({s}).'
				else:
					s = f'"Match n CVEs condition" with index {i} was met. At least {conditions["match_n_CVEs_conditions"][i]["n"]} CVE(s) meet the specified conditions ({s}).'
				met_cve_conditions.append(s)
				disj = True 
			else:
				conj = False
	if conjunction:
		return conj, met_cve_conditions
	return disj, met_cve_conditions

def check_cve_numbers(conditions, cves, name, days, conjunction, found=False):
	conj = True
	disj = False
	met_cve_conditions = []
	if "number_CVEs" in conditions:
		if len(cves) >= conditions["number_CVEs"]:
			s = f'Number of CVEs ({len(cves)}) is greater than or equal to threshold {conditions["number_CVEs"]}.'
			met_cve_conditions.append(s)
			disj = True
		else:
			conj = False
	if "number_actively_exploited_CVEs" in conditions:
		if sum(cves.values()) >= conditions[f"number_actively_exploited_CVEs"]:
			s = f'Number of actively exploited CVEs ({sum(cves.values())}) is greater than or equal to threshold {conditions["number_actively_exploited_CVEs"]}.'
			met_cve_conditions.append(s)
			disj = True
		else:
			conj = False
	if "fraction_actively_exploited_CVEs" in conditions:
		if (sum(cves.values()) / len(cves)) >= conditions["fraction_actively_exploited_CVEs"]:
			s = f'Fraction of actively exploited CVEs ({(sum(cves.values()) / len(cves))}) is greater than or equal to threshold {conditions["fraction_actively_exploited_CVEs"]}.'
			met_cve_conditions.append(s)
			disj = True
		else:
			conj = False
	if conjunction:
		return conj, met_cve_conditions
	return disj, met_cve_conditions

def check_formula_condition(formula, cves):
	l = []
	d = dict()
	result = False
	s = ""
	for cve in cves:
		formula_result = read_formula(formula["formula"], cve, cves[cve])
		l.append(formula_result)
		if formula_result in d:
			d[formula_result].append(cve)
		else:
			d[formula_result] = [cve]
	if formula["comparison"] == "average":
		if (sum(l) / len(l)) >= formula["threshold"]:
			result = True
			s = f'CVEs had an average score for formula "{formula["formula"]}" ({(sum(l) / len(l))}) greater than or equal to threshold {formula["threshold"]}.'
	if formula["comparison"] == "max":
		l.sort(reverse=True)
		if l[0] >= formula["threshold"]:
			result = True
			condition_cve = d[l[0]][0]
			s = f'CVEs had an max score for formula "{formula["formula"]}" ({l[0]}, {condition_cve}) greater than or equal to threshold {formula["threshold"]}.'
	if formula["comparison"] == "sum":
		if sum(l) >= formula["threshold"]:
			result = True
			s = f'CVEs had an summed score for formula "{formula["formula"]}" ({sum(l)}) greater than or equal to threshold {formula["threshold"]}.'
	if formula["comparison"] == "n_above":
		n = formula["n"]
		if len(l) >= n:
			l.sort(reverse=True)
			if l[n-1] >= formula["threshold"]:
				result = True
				condition_cves = []
				for formula_result in l[n-1:]:
					condition_cves = condition_cves + d[formula_result]
				s = f' At least {n} CVE(s) ({condition_cves}) had a score for formula "{formula["formula"]}" greater than or equal to the threshold {formula["threshold"]}.'
	return result, s

def check_match_n_CVEs_condition(condition, cves):
	if not "n" in condition:
		logging.error(f'`match_n_CVEs_conditions` must contain the value "n". Please update the configuration file.')
		sys.exit(1)
	matches = []
	for cve in cves:
		match_strings = []
		match = True
		# check every condition is met
		for score in ["baseScore", "exploitabilityScore", "impactScore", "is_actively_exploited"]:
			if score in condition:
				if cves[cve][score] < condition[score]:
					match = False
					break
				else:
					match_strings.append(f'{score} of {cves[cve][score]} is greater than or equal to {condition[score]}')
		if "formulas" in condition:
			for formula in condition["formulas"]:
				formula_result = read_formula(formula["formula"], cve, cves[cve])
				if formula_result < formula["threshold"]:
					match = False
				else:
					match_strings.append(f'formula "{formula["formula"]}" of {formula_result} is greater than or equal to {formula["threshold"]}')
		if match == True:
			matches.append(f'{cve} : {", ".join(match_strings)}')
	return len(matches) >= condition["n"], "; ".join(matches)

def is_CVE_score_condition(conditions):
	for condition in ["max_baseScore", "max_exploitabilityScore", "max_impactScore", "average_baseScore", "average_exploitabilityScore", "average_impactScore"]:
		if condition in conditions:
			return True
	if "formulas" in conditions:
		if len(conditions["formulas"]) > 0:
			return True
	if "match_n_CVEs_conditions" in conditions:
		if len(conditions["match_n_CVEs_conditions"]) > 0:
			return True
	return False


# ----------------------------------------
#           CISA compliance
# ----------------------------------------
def update_days_from_CISA(cves, days, release_date):
	result_date = None
	result_cve = None
	cves = sorted(list(cves.keys()))
	oldest_cve_year = int(cves[0][4:8]) # CISA entry will be older than CVE
	cisa_data = get_CISA_data()
	for cisa_cve in reversed(cisa_data["vulnerabilities"]):
		# don't need to check oldest CISA entries
		if int(cisa_cve["dateAdded"][0:4]) < oldest_cve_year :
			break
		else:
			# CISA entry is new enough to check: so is this a relevant cve?
			if cisa_cve["cveID"] in cves:
				# cve is relevant, so replace result is due date is earlier
				if result_date:
					if datetime.datetime.strptime(cisa_cve["dueDate"], CISA_DATE_FORMAT) < result_date:
						result_date = datetime.datetime.strptime(cisa_cve["dueDate"], CISA_DATE_FORMAT)
						result_cve = cisa_cve["cveID"]
				else:
					result_date = datetime.datetime.strptime(cisa_cve["dueDate"], CISA_DATE_FORMAT)
					result_cve = cisa_cve["cveID"]
	# calc days from date
	if result_date:
		cisa_days = max(0, (result_date - datetime.datetime.strptime(release_date, DATE_FORMAT)).days)
		logging.info(f"CISA requires {result_cve} to be patched on {result_date.strftime(CISA_DATE_FORMAT)}, {cisa_days} day(s) after release.")
		if cisa_days < days:
			return cisa_days
	return days

def get_CISA_data():
	req = urllib.request.Request(url=CISA_URL, headers=HEADERS, method="GET")
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		logging.error(f"Unexpected HTTP response \"{e}\" while trying to get CISA feed.")
		sys.exit(1)
	try:
		result = json.loads(response.read().decode('utf-8'))
		logging.info("Successfully loaded macOS release data from CISA!")
	except Exception as e:
		logging.error("Unable to load macOS release data from CISA.")
		sys.exit(1)
	return result

# ----------------------------------------
#              User input
# ----------------------------------------
def user_confirm(days, target, version, old_version):
	print(f'Should target \"{target}\" be updated from from {old_version} to {version} {days} day(s) after release? [y/n] ', end='')
	while True:
		try:
			return _BOOLMAP[str(input()).lower()]
		except Exception as e:
			print('Please respond with \'y\' or \'n\'.\n')

# ----------------------------------------
#                 Main
# ----------------------------------------
def process_options():
	parser = optparse.OptionParser()
	parser.set_usage('Usage: %prog [options]')
	parser.add_option('--sofa-url', '-s', dest='sofa_url', default=DEFAULT_SOFA_FEED,
						help="Custom SOFA feed URL. Should include the path to macos_data_feed.json.\nDefaults to https://sofa.macadmins.io/v1/macos_data_feed.json")
	parser.add_option('--nudge-file', '-n', dest='nudge_file', default = DEFAULT_NUDGE_FILENAME,
						help="The Nudge JSON config file to update.\nDefaults to nudge-config.json")
	parser.add_option('--api-key', dest='api_key',
						help="A VulnCheck API key for getting CVE data. It is required to either set this argument, or the VULNCHECK_API_KEY environment variable.")
	parser.add_option('--config-file', '-c', dest='config_file',
						help="The path to a yaml-formatted file containing the configuration for nudge-auto-updater")
	parser.add_option('--webhook-url', '-w', dest='webhook_url',
						help=f'Optional url for slack webhooks.')
	parser.add_option('--markdown-file', '-m', dest='markdown_file',
						help=f'Optional file name to print markdown summary when nudge file is updated.')
	parser.add_option('--auto', action='store_true',
						help='Run without interaction.')
	parser.add_option('--force', '-f', action='store_true',
						help='Force re-evaluation of urgency and required installation date for every targetedOSVersionsRule, even when requiredMinimumOSVersion in Nudge JSON config is up to date.')
	parser.add_option('--cisa', action='store_true',
						help='Sets required installation date to be CISA compliant, if your CISA recommends a sooner required installation date than your configuration.')
	options, _ = parser.parse_args()
	# chack if api key in env
	api_key = options.api_key
	if (not api_key) and os.environ.get("VULNCHECK_API_KEY"):
		api_key = os.environ.get("VULNCHECK_API_KEY")
	# check if slack url in env
	slack_url = options.webhook_url
	if (not slack_url) and os.environ.get("SLACK_WEBHOOK"):
		slack_url = os.environ.get("SLACK_WEBHOOK")
	# return based on config file option
	if options.config_file:
		return options.sofa_url, options.nudge_file, api_key, options.config_file, True, slack_url, options.markdown_file, options.auto, options.force, options.cisa
	return options.sofa_url, options.nudge_file, api_key, DEFAULT_CONFIG_FILE_NAME, False, slack_url, options.markdown_file, options.auto, options.force, options.cisa

def setup_logging():
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(asctime)s - %(levelname)s (%(module)s): %(message)s",
		datefmt='%d/%m/%Y %H:%M:%S',
		stream=sys.stdout)

def main():
	setup_logging()
	sofa_url, nudge_file_name, api_key, config_file_name, is_config_specified, slack_url, md_file, auto, force, cisa_compliant = process_options()
	nudge_file_dict, nudge_requirements = get_nudge_config(nudge_file_name)
	latest_macos_releases, cves, urls, release_dates = get_macos_data(sofa_url)
	latest_macos_releases.sort(reverse=True)
	config = get_config(config_file_name, is_config_specified)
	nudge_file_needs_updating = False
	if slack_url:
		slack_blocks = setup_slack_blocks()
	if md_file:
		md = ""

	# check if we need CVE scores
	are_cve_scores_needed = check_if_cve_scores_needed(config, api_key)

	# check per configuration if it needs to be updates
	for target in config["targets"]:
		if not target["target"] in nudge_requirements:
			logging.warning(f"No nudge configuration exists for target \"{target['target']}\", despite this target being specified in {config_file_name}.")
			logging.warning(f"Skipping \"{target['target']}\"")
		else:
			# nudge requirement needs to be checked
			new_macos_release = nudge_requirements[target["target"]]["version"]
			if target["update_to"] == "latest":
				# nudge requirement needs to be checked against latest macOS
				if nudge_requirements[target["target"]]["version"] < latest_macos_releases[0]:
					is_uptodate = False
					new_macos_release = latest_macos_releases[0]
					logging.info(f"Nudge configuration for target \"{target['target']}\" needs to be updated from {nudge_requirements[target['target']]['version']} to {new_macos_release}.")
				else:
					is_uptodate = True
			else:
				config_version_gt = get_gt_config_target(target["update_to"])
				is_uptodate = True
				for macos_release in latest_macos_releases:
					if macos_release < config_version_gt and macos_release > nudge_requirements[target["target"]]["version"]:
						logging.info(f"Nudge configuration for target \"{target['target']}\" needs to be updated from {nudge_requirements[target['target']]['version']} to {macos_release}.")
						is_uptodate = False
						new_macos_release = macos_release
						break
			if (not force) and is_uptodate:
				logging.info(f"Nudge configuration for target \"{target['target']}\" is already up to date.")
			else:
				# nudge is not up to date or we are forcing a re-evaluation! 
				if (force) and is_uptodate:
					logging.info(f"Nudge configuration for target \"{target['target']}\" is already up to date. Forcing re-evaluation of urgency and required installation date.")
				# How urgent is the new update?
				# get security metrics
				security_release_cves_scores = dict()
				security_release_cves = cves[str(new_macos_release)]
				# do we need cve scores?
				if are_cve_scores_needed:
					# CVE scores needed  so get scores for each CVE:
					for cve in security_release_cves:
						cve_scores = get_CVE_scores(cve, security_release_cves[cve], api_key)
						if cve_scores:
							security_release_cves_scores[cve] = cve_scores
				# check urgency levels to determine deadline
				urgency_condition_met = False
				met_cve_conditions = []
				if "cve_urgency_levels" in config:
					for i, cve_urgency_level in enumerate(config["cve_urgency_levels"]):
						if not urgency_condition_met:
							name = f"level {i}"
							if "name" in cve_urgency_level:
								name = cve_urgency_level["name"]
							if "deadline_days" not in cve_urgency_level:
								logging.error(f"Target \"{target['target']}\" is missing value \'deadline_days\'. Please add this value to {config_file_name}")
								sys.exit(1)
							days = cve_urgency_level["deadline_days"]
							conjunction = False
							if "conjunction" in cve_urgency_level:
								conjunction = cve_urgency_level["conjunction"]
							is_urgency_level_met, urgency_level_description, met_cve_conditions = check_deadline_urgent(cve_urgency_level["cve_urgency_conditions"], security_release_cves_scores, security_release_cves, name, days, conjunction)
							if is_urgency_level_met:
								urgency_condition_met = True
								break
				if not urgency_condition_met:
					days = config["default_deadline_days"]
					s = f"No CVE urgency level met. Installation will be required {days} day(s) after release."
					logging.info(s)
					urgency_level_description = s 
				# check CISA date
				if cisa_compliant:
					days = update_days_from_CISA(security_release_cves, days, release_dates[str(new_macos_release)])
				# update target
				if auto or user_confirm(days, target['target'], new_macos_release, nudge_requirements[target['target']]['version']):
					nudge_file_needs_updating = True
					nudge_file_dict = update_nudge_file_dict(nudge_file_dict, target["target"], new_macos_release, urls[str(new_macos_release)], release_dates[str(new_macos_release)], days)
					if slack_url:
						target_description = f'Target \"{target["target"]}\" was updated from from {nudge_requirements[target["target"]]["version"]} to {new_macos_release}.'
						slack_blocks = add_to_slack_block(slack_blocks, urgency_condition_met, target_description, urgency_level_description, met_cve_conditions)
					if md_file:
						md += md_description(urgency_condition_met, target_description, urgency_level_description, met_cve_conditions)
					if not auto:
						logging.info("Nudge configuration will be updated.")
				else:
					logging.info("Skipping update.")
	# if nudge dict has changed rewrite it
	if nudge_file_needs_updating:
		write_nudge_config(nudge_file_name, nudge_file_dict)
		logging.info("Nudge configuration updated.")
		if slack_url:
			send_slack_webhook(slack_url, slack_blocks)
		if md_file:
			write_md_file(md_file, md)
	else:
		logging.info("Nudge configuration does not need updating.")

if __name__ == '__main__':
	main()
