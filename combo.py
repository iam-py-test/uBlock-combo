import requests
import os
lists = {"DandelionSprout Antimalware":"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt","The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antimalware.txt","uBlock Filters":"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt","Easylist":"https://easylist.to/easylist/easylist.txt","PUP Filter":"https://curben.gitlab.io/malware-filter/pup-filter.txt"}

mainlist = """! Title: uBlock combo list
! Expires: 1 day

"""

for list in lists:
  l = requests.get(lists[list]).text
  mainlist += "\n! ----- BEGIN {} -----\n".format(list)
  mainlist += l
with open("list.txt","w") as f:
  f.write(mainlist)
  f.close()
