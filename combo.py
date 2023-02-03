import requests
import os
import urllib.parse
import re
lists = {"Dandelion Sprout's Anti-Malware List":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt","The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antimalware.txt","The anti-typo list":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antitypo.txt","Actually Legitimate URL Shortener Tool":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt"}

donelines = []
donedomains = []
excludes = []

def extdomain(line):
	try:
		domain = ""
		if line.startswith("||") and line.endswith("^$all"):
			domain = line[2:-6]
		elif line.startswith("||") and line.endswith("^$all,~inline-font,~inline-script"):
			domain = line[2:-33]
		return domain
	except:
		return ""

mainlist = """! Title: iam-py-test's Combo List
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/uBlock-combo
! the Python script and my two lists are under CC0 
! for Dandelion Sprout's Anti-Malware List and Actually Legitimate URL Shortener Tool, see https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md

"""

eadd = 0
ered = 0

replacecomments = re.compile("!.*\n")

for clist in lists:
	l = requests.get(lists[clist]).text.replace("! Title: ","! List title: ").split("\n")
	mainlist += "\n! ----- BEGIN {} -----\n".format(clist)
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
		elif line.startswith("!#include "):
			try:
				incpath = urllib.parse.urljoin(lists[clist],line[10:],allow_fragments=True)
				inccontents = requests.get(incpath).text.replace("! Title","! Included title").replace("[Adblock Plus 3.6]","")
				try:
					inccontents = re.sub(replacecomments,inccontents,"")
				except:
					# if the regex fails, just continue on
					pass
				mainlist += "{}\n".format(inccontents)
			except Exception as err:
				print(line,err)
		else:
			mainlist += "{}\n".format(line)
			eadd += 1
			donelines.append(line)
			edomain = extdomain(line)
			if edomain != "":
				donedomains.append(edomain)
mainlist = mainlist.replace("[Adblock Plus 3.8]","").replace("[Adblock Plus 3.6]","")
with open("list.txt","w",encoding="UTF-8") as f:
	f.write(mainlist)
	f.close()
print("Complete")
print("""Stats:
{} entries added
{} redundant entries removed
{} domains added
""".format(eadd,ered,len(donedomains)))
