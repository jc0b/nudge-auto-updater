# nudge-auto-updater
`nudge-auto-updater` is a tool that leverages [SOFA](https://sofa.macadmins.io) in combination with [VulnCheck](https://docs.vulncheck.com/) to detect new macOS updates, triage the severity of the CVEs fixed, and update your JSON [Nudge](https://github.com/macadmins/Nudge) configuration appropriately.

## Getting started
To get started with nudge-auto-updater, you should read the ["Getting Started" page](https://github.com/jc0b/nudge-auto-updater/wiki/Home) in the wiki.

Information about configuring nudge-auto-updater can be found in [the configuration documentation](https://github.com/jc0b/nudge-auto-updater/wiki/Supported-Configuration-Keys). [Examples](https://github.com/jc0b/nudge-auto-updater/wiki/Example-Configurations) are also provided.

If you want to leverage the VulnCheck functionality, then you will need to provide your own [VulnCheck API key](https://vulncheck.com/token/newtoken). You can supply this key to the script by means of an [environment variable](https://github.com/jc0b/nudge-auto-updater/wiki/Environment-Variables), or a [command-line argument](https://github.com/jc0b/nudge-auto-updater/wiki/Command-line-Arguments).