# nudge-auto-updater
A tool to demo how you can update [Nudge](https://github.com/macadmins/Nudge) JSON configuration definitions automatically.

Leverages [SOFA](https://sofa.macadmins.io) for the macOS update feed, and [NIST's National Vulnerability Database REST API](https://nvd.nist.gov/developers/vulnerabilities) for grabbing info about CVEs.

## Configuration
You can configure this program by having a `configuration.yml` file.
This `configuration.yml` file should contain a list of `osVersionRequirements`, specifying the following keys:
- target : Specifies the `targetedOSVersionsRule` as a string.
- update_to : Specifies the macOS version this target should update to as a string. This value can be "latest" if the `requiredMinimumOSVersion` should be the latest version of MacOs. Otherwise this value should be a major version (e.g. 13), a minor version (e.g. 13.1) or a patch version (e.g. 13.1.1). In this case the `requiredMinimumOSVersion` will update to the newest MacOs version with a major version, minor version or patch version up to (inclusively) the specified value.

If the `configuration.yml` file is missing this program will only update the Nudge configuration `osVersionRequirements` for the default `targetedOSVersionsRule` to the latest version of macOS.
An example file is included in this project.