import os
import re
from statistics import mean

results = list()
content = None

with open("log.data") as file:
  content = file.readlines()

content = [x.strip() for x in content]
for line in content:
  m = re.search('average time per credential:  (.+)', line)
  if m:
    results.append(float(m.group(1)))

print(results)
print(mean(results))