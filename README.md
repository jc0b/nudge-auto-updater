# nudge-auto-updater
`nudge-auto-updater` is a tool that leverages [SOFA](https://sofa.macadmins.io) in combination with [VulnCheck](https://docs.vulncheck.com/) to detect new macOS updates, triage the severity of the CVEs fixed, and update your JSON [Nudge](https://github.com/macadmins/Nudge) configuration appropriately.

A [VulnCheck API key](https://vulncheck.com/token/newtoken) is required to use this script - without it, CVE lookups can't be performed.

## Getting started
To get started with nudge-auto-updater, you should read the ["Getting Started" page](https://github.com/jc0b/nudge-auto-updater/wiki/Home) in the wiki.

Information about configuring nudge-auto-updater can be found in [the configuration documentation](https://github.com/jc0b/nudge-auto-updater/wiki/Supported-Configuration-Keys). [Examples](https://github.com/jc0b/nudge-auto-updater/wiki/Example-Configurations) are also provided.