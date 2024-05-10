# nudge-auto-updater
`nudge-auto-updater` is a tool that leverages [SOFA](https://sofa.macadmins.io) in combination with [VulnCheck](https://docs.vulncheck.com/) to detect new macOS updates, triage the severity of the CVEs fixed, and update your JSON [Nudge](https://github.com/macadmins/Nudge) configuration appropriately.

A VulnCheck API key is currently required to use this script - without it, CVE lookups can't be performed.

## Configuration
You can configure this program by putting a `configuration.yml` file in the same directory as the script.
Under the key `targets`, this `configuration.yml` file should contain a list of `osVersionRequirements`, the keys of which are documented below:
|	Key	| Type | Description	|
|-----------------------|--------|----------------------|
| `target` | string | Specifies the `targetedOSVersionsRule` in Nudge. |
| `update_to` | string | Specifies the macOS version this target should update to. This value can be "latest" if the `requiredMinimumOSVersion` should be the latest version of macOS. Otherwise this value can be a major version (e.g. 13), a minor version (e.g. 13.1) or a specific patch version (e.g. 13.1.1). In this case the `requiredMinimumOSVersion` will be set to the newest macOS version with a major version, minor version or patch version less than or equal to the specified value. |

To do: describe rest of keys 

If the `configuration.yml` file is missing this script will only update the Nudge configuration `osVersionRequirements` for the default `targetedOSVersionsRule` to the latest version of macOS.
The specified configuration will only update existing `osVersionRequirements` - it will not create new ones.
An example file is included in this project.