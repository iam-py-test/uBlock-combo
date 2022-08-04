import requests
import os
lists = {"Dandelion Sprout's Anti-Malware List":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt","The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antimalware.txt","The anti-typo list":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antitypo.txt","Actually Legitimate URL Shortener Tool":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt"}

mainlist = """! Title: uBlock combo list
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/uBlock-combo
! the Python script and my two lists are under CC0 
! for Dandelion Sprout's Anti-Malware List and Actually Legitimate URL Shortener Tool, see https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md

"""

for list in lists:
  l = requests.get(lists[list]).text.replace("[Adblock Plus 3.6]","").replace("! Title: ","! List title: ")
  mainlist += "\n! ----- BEGIN {} -----\n".format(list)
  mainlist += l
with open("list.txt","w") as f:
  f.write(mainlist)
  f.close()
print("Complete")
