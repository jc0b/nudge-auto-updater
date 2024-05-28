# nudge-auto-updater
`nudge-auto-updater` is a rule-based updater for [Nudge](https://github.com/macadmins/Nudge) JSON files that sources lists of CVEs from [SOFA](https://sofa.macadmins.io), and enriches them with information from the National Vulnerability Database (via [VulnCheck](https://docs.vulncheck.com/)).
Armed with this information, and your configured rules, it can determine whether a new macOS update has been released that should be applied. If so, it can decide enforcement deadlines, provide output as to what rules it followed to reach that decision, and then update your Nudge JSON config file accordingly. Optionally, you can have `nudge-auto-updater` bring your existing Nudge JSON configuration in-line with your specified rules, even if the enforced version is already up-to-date.

## Getting started
To get started with nudge-auto-updater, you should read the ["Getting Started" page](https://github.com/jc0b/nudge-auto-updater/wiki/Home) in the wiki.

Information about configuring nudge-auto-updater can be found in [the configuration documentation](https://github.com/jc0b/nudge-auto-updater/wiki/Supported-Configuration-Keys). [Examples](https://github.com/jc0b/nudge-auto-updater/wiki/Example-Configurations) are also provided.

If you want to leverage the VulnCheck functionality, then you will need to provide your own [VulnCheck API key](https://vulncheck.com/token/newtoken). You can supply this key to the script by means of an [environment variable](https://github.com/jc0b/nudge-auto-updater/wiki/Environment-Variables), or a [command-line argument](https://github.com/jc0b/nudge-auto-updater/wiki/Command-line-Arguments).

