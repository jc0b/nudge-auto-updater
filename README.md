# nudge-auto-updater
A tool to demo how you can update [Nudge](https://github.com/macadmins/Nudge) JSON configuration definitions automatically.

Leverages [SOFA](https://sofa.macadmins.io) for the macOS update feed, and [NIST's National Vulnerability Database REST API](https://nvd.nist.gov/developers/vulnerabilities) for grabbing info about CVEs.

## Configuration
You can configure this program by putting a `configuration.yml` file in the same directory as the script.
This `configuration.yml` file should contain a list of `osVersionRequirements`, the keys of which are documented below:
|	Key	| Type | Description	|
|-----------------------|--------|----------------------|
| `target` | string | Specifies the `targetedOSVersionsRule` in Nudge. |
| `update_to` | string | Specifies the macOS version this target should update to. This value can be "latest" if the `requiredMinimumOSVersion` should be the latest version of macOS. Otherwise this value can be a major version (e.g. 13), a minor version (e.g. 13.1) or a specific patch version (e.g. 13.1.1). In this case the `requiredMinimumOSVersion` will be set to the newest macOS version with a major version, minor version or patch version less than or equal to the specified value. |

If the `configuration.yml` file is missing this program will only update the Nudge configuration `osVersionRequirements` for the default `targetedOSVersionsRule` to the latest version of macOS.
The specified configuration will only update existing `osVersionRequirements` - it will not create new ones.
An example file is included in this project.