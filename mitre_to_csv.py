import csv
import json
import requests
import re

def minimd(s, fmt="text"):
	code = re.compile('<code>(?P<codeblock>.*?)</code>')
	bold = re.compile(r'\*\*(.*?)\*\*')
	link = re.compile(r'\[([^[]*?)\]\((.*?)\)')
	header = re.compile(r'(?:^|\n)#+([^\n]*)')

	if fmt == "html":
		s = code.sub(lambda x: '<code>{}</code>'.format(x.group('codeblock').replace('<', '&lt;')), s)
		s = bold.sub(r'<b>\1</b>', s)
		s = link.sub(r'<a href="\2">\1</a>', s)
		s = header.sub(r'<b><u>\1</u></b><br/>', s)
		mtil = re.compile(r'"https://attack.mitre.org/techniques/(?P<technique>.*?)"')
		s = mtil.sub(lambda x: '"#{}"'.format(x.group('technique').replace('/', '.')), s)
		s = s.replace('\n', '<br/>')
	elif fmt == "text":
		s = header.sub(r'# \1 #\n', s)
		s = code.sub(lambda x: '`{}`'.format(x.group('codeblock')), s)
		mtil = re.compile(r'https://attack.mitre.org/(techniques|tactics|software)/(?P<technique>[^\])"]+)')
		s = mtil.sub(lambda x: '{}'.format(x.group('technique').replace('/', '.')), s)
		s = s.replace('<br>', '\n')
	return s

def generate_mitre_csv(outfile="Files/mitre.csv", url="https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"):
	print("Fetching latest enterprise-attack.json ...")
	d = requests.get(url)
	assert d.status_code == 200, "Failure fetching URL"

	print("Parsing file ...")
	j = d.json()
	assert 'spec_version' in j, "Missing version info"
	assert 'objects' in j, "Missing objects"
	assert j['spec_version'] == '2.0', "Unsupported STIX version"

	o = {}
	for i in j['objects']:
		assert 'type' in i, f"Missing type in entry {i}"
		assert 'id' in i, f"Missing id in entry {i}"
		if i.get('revoked') or i.get('x_mitre_deprecated'):
			continue
		t = i['type']
		id = i['id']
		if t not in o:
			o[t] = {}
		o[t][id] = i

	#print("Generating list of tactics ...")
	tactics = {}
	for t in o.get('x-mitre-tactic', {}):
		tac = o['x-mitre-tactic'][t]
		short_name = tac["x_mitre_shortname"]
		name = tac["name"]
		tactics[short_name] = name

	#print("Generating list of techniques ...")
	tech = {}
	for tn in o.get('attack-pattern', {}):
		t = o['attack-pattern'][tn]
		mitre_id = ""
		mitre_url = ""
		for r in t.get('external_references', []):
			if r.get('source_name') == 'mitre-attack':
				mitre_id = r.get('external_id', "")
				mitre_url = r.get('url', "")
		assert mitre_id, f"Missing MITRE ID for {t}"
		name = t.get('name', "")
		platforms = t.get('x_mitre_platforms', [])
		kill_chain_phases = t.get('kill_chain_phases', [])
		kill_chain_phases = [tactics[x['phase_name']] for x in kill_chain_phases if x['kill_chain_name'] == "mitre-attack"]
		data_sources = t.get('x_mitre_data_sources', [])
		description = minimd(t.get('description', ""))
		detection = minimd(t.get('x_mitre_detection', ""))
		tech[mitre_id] = (name, tn, mitre_url, platforms, kill_chain_phases, data_sources, detection, description)

	#print("Generating Mitre - Attacks & Techniques CSV file ...")
	with open(outfile, 'w', newline='\n') as out:
		writer = csv.DictWriter(out, ['name', 'id', 'url', 'platforms', 'kill chain phases', 'description', 'data sources', 'detection'], quoting=csv.QUOTE_ALL)
		writer.writeheader()
		for tid in sorted(tech.keys()):
			t = tech[tid]
			writer.writerow({
				'name': t[0],
				'id': tid,
				'url': t[2],
				'platforms': ', '.join(t[3]),
				'kill chain phases': ', '.join(t[4]),
				'description': t[7],
				'data sources': ', '.join(t[5]),
				'detection': t[6]
			})

	print(f"Mitre - Attacks & Techniques CSV file saved to: {outfile}")
	return outfile 
#generate_mitre_csv("Files/mitre.csv")
