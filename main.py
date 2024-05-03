#!/usr/bin/env python3
import json
import logging
import sys

DEFAULT_DEADLINE_DAYS = 14
URGENT_DEADLINE_DAYS = 7

class Version:
	major = minor = patch = 0

	def __init__(self, a, b=None, c=0):
		# takes as input (major, minor, patch=0) or (s, source=None)
		if isinstance(a, int) and isinstance(b, int):
			self._process_version_ints(a, b, c)
		elif isinstance(a, str):
			self._process_version_str(a, b)
		else:
			logging.error(f"Unable to interpret Version from {a}, {b}, {c}.")
			sys.exit(1)
	
	@classmethod
	def from_str(cls, s: str, source=None):
		return cls(s, source)

	@classmethod
	def from_ints(cls, major, minor, patch=0):
		return cls(major, minor, patch)

	@classmethod
	def from_int(cls, major, minor, patch=0):
		return cls(major, minor, patch)

	def _process_version_ints(self, major:int, minor:int, patch:int):
		self.major = major
		self.minor = minor
		self.patch = patch

	def _process_version_str(self, s:str, source:str):
		parts = s.split(".")
		if len(parts) < 2:
			if source :
				logging.error(f"Got an invalid version number from {soure}.")
			else :
				logging.error("Failed to format version number.")
			sys.exit(1)
		self.major = int(parts[0])
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
		data = json.load(f)
	except e:
		logging.error("Unable to open nudge-config.json")
		sys.exit(1)

	logging.info("Successfully loaded Nudge config!")
	return data

def get_macos_data() -> Version:
	# to do
	# currently returning a default
	return Version(14, 5)

def write_nudge_config(dict):
	pass

def main():
	nudge_config = get_nudge_config()
	latest_macos_release = get_macos_data()

	# if nudge_config["osVersionRequirements"]
	# check whether the macOS feed has a macOS version
	# newer than enforced by Nudge
	# if not, exit here already

	# if yes, we can assess the CVEs to determine the relevant deadline

	write_nudge_config(nudge_config)

	# test stuff
	get_macos_data()


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
