# uBlock combo list (*not* affiliated with uBlock Origin)
A filterlist compiled out of other filterlists to block malware, scams, phishing, and remove tracking parameters in uBlock Origin and AdGuard, with most redundant entries automatically removed. <br>
All issues with the included lists should be reported upstream.<br>
Note: This is designed to work _alongside_ the default lists in your content blocker. It can not replace them.

## Licensing note
The Python script and my lists are under CC0. DandelionSprout's lists (Dandelion Sprout's Anti-Malware List and Actually Legitimate URL Shortener Tool) [are under the Dandelicence](https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md).

### Lists used
- [Dandelion Sprout's Anti-Malware List](https://github.com/DandelionSprout/adfilt)
- [Actually Legitimate URL Shortener Tool](https://github.com/DandelionSprout/adfilt)
- [The malicious website blocklist (lite)](https://github.com/iam-py-test/my_filters_001/blob/main/antimalware.txt)
- [iam-py-test's antitypo list](https://github.com/iam-py-test/my_filters_001/blob/main/antitypo.txt)

### Mentions
- [Listed as an "all-purpose" list by yokoffing](https://github.com/yokoffing/filterlists#all-purpose)

#### Note about the usage of The malicious website blocklist (lite)
The lite version of the Malicious Website Blocklist includes several changes from the original. The lite version excludes subdomains of already blocked domains, dead domains, and known false positives. These exclusions make the list have several hundred fewer entries. As such, it is more suited for this type of combined list than the original.

