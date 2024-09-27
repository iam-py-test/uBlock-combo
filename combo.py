import requests
import os
import urllib.parse
import re
import datetime
import publicsuffixlist


psl = publicsuffixlist.PublicSuffixList()

LIST_FILENAME = "list.txt"
STATUS_FILENAME = "status.txt"
DOMAIN_FILENAME = "domains.txt"
lists = {
	"Dandelion Sprout's Anti-Malware List":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
	"The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_lite.txt",
	"iam-py-test's antitypo list":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antitypo.txt",
	"Actually Legitimate URL Shortener Tool":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt"
}

donelines = []
donedomains = []
excludes = requests.get("https://raw.githubusercontent.com/iam-py-test/allowlist/main/filter.txt").text.split("\n")
subdomains = requests.get("https://raw.githubusercontent.com/iam-py-test/tracker_analytics/main/kdl.txt").text.split("\n")
subdomains += requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
subdomains += requests.get("https://raw.githubusercontent.com/iam-py-test/cloudflare-usage/main/cnames.txt").text.split("\n")
dead = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/refs/heads/main/dead.mwbcheck.txt").text.split("\n")

# https://www.geeksforgeeks.org/how-to-validate-an-ip-address-using-regex/
is_ip_v4 = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
is_ip_v6 = "((([0-9a-fA-F]){1,4})\\:){7}"\
             "([0-9a-fA-F]){1,4}"
is_ip_v4_reg = re.compile(is_ip_v4)
is_ip_v6_reg = re.compile(is_ip_v6)

def isipdomain(domain):
	if re.search(is_ip_v4_reg,domain):
		return True
	if re.search(is_ip_v6_reg,domain):
		return True
	return False

def extdomain(line):
	try:
		domain = ""
		if line.startswith("||") and line.endswith("^$all"):
			domain = line[2:-5]
		if line.startswith("||") and line.endswith("^$doc"):
			domain = line[2:-5]
		if line.startswith("||") and line.endswith("^$document"):
			domain = line[2:-10]
		if line.startswith("||") and line.endswith("^$3p"):
			domain = line[2:-5]
		elif line.startswith("||") and line.endswith("^$all,~inline-font,~inline-script"):
			domain = line[2:-33]
		elif line.startswith("||") and line.endswith("^"):
			domain = line[2:-1]
		elif line.startswith("||") and line.endswith("^$all,~inline-font"):
			domain = line[2:-18]
		elif line.startswith("||") and line.endswith("^$doc,popup"):
			domain = line[2:-11]
		elif line.startswith("||") and line.endswith("^$all,~inline-script"):
			domain = line[2:-20]
		return domain
	except:
		return ""

mainlist = """! Title: iam-py-test's Combo List
! Expires: 1 day
! Script last updated: 22/11/2023
! Last updated: {}
! Homepage: https://github.com/iam-py-test/uBlock-combo
! the Python script and my two lists are under CC0 
! for Dandelion Sprout's Anti-Malware List and The Actually Legitimate URL Shortener Tool, see https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md

""".format(datetime.date.today().strftime("%d/%m/%Y"))

eadd = 0
ered = 0
parselist = None

def parselist(l,curl=""):
	global donedomains
	global donelines
	global eadd
	global ered
	plist = ""
	for line in l:
		if (line.startswith("!") or line.startswith("#")) and "include" not in line:
			continue
		elif line.startswith("[Adblock") and line.endswith("]"):
			continue
		elif line in donelines:
			ered += 1
		elif line in excludes:
			continue
		elif line == "":
			continue
		elif extdomain(line) != "" and extdomain(line) in donedomains:
			continue
		elif extdomain(line) in dead:
			continue
		elif line.startswith("!#include "):
			try:
				incpath = urllib.parse.urljoin(curl,line[10:], allow_fragments=True)
				inccontents = requests.get(incpath).text.replace("\r", "").split("\n")
				endcontents = parselist(inccontents, incpath)
				plist += "{}\n".format(endcontents)
			except Exception as err:
				print(line,err)
		else:
			plist += "{}\n".format(line)
			eadd += 1
			donelines.append(line)
			edomain = extdomain(line)
			if edomain != "" and edomain != " ":
				donedomains.append(edomain)
	return plist

for clist in lists:
	l = requests.get(lists[clist]).text.split("\n")
	mainlist += parselist(l,lists[clist])

with open(LIST_FILENAME,"w",encoding="UTF-8") as f:
	f.write(mainlist)
	f.close()
justdomains = []
for d in donedomains:
	if "/" not in d and "." in d and "*" not in d and d != "" and d.endswith(".") == False and isipdomain(d) == False:
		justdomains.append(d)
with open(DOMAIN_FILENAME, "w", encoding="UTF-8") as f:
	f.write("\n".join(justdomains))
	f.close()

subsfound = 0
domainplussub = justdomains
for sub in subdomains:
	try:
		maindomain = psl.privatesuffix(sub)
		if maindomain in domainplussub and sub not in domainplussub:
			subsfound += 1
			domainplussub.append(sub)
	except Exception as err:
		print(err, sub)

with open("domains_subdomains.txt", "w", encoding="UTF-8") as f:
	f.write("\n".join(justdomains))
	f.close()

with open(STATUS_FILENAME,'w') as status:
	status.write("""Stats:
{} entries added
{} redundant entries removed
{} domains added
{} subdomains added
""".format(eadd,ered,len(donedomains), subsfound))
	status.close()
