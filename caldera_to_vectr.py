import json
import csv
from pathlib import Path
from datetime import datetime
from mitre_to_csv import generate_mitre_csv

def iso_to_epoch(ts):
    try:
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
    except:
        return ''


def flatten_json(y, parent_key='', sep='.'):
    items = []
    for k, v in y.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def caldera_to_vectr(input_json_path, output_csv_path):

    mitre_csv_path = Path(generate_mitre_csv("Files/mitre.csv"))

    field_map = {
        'operation_metadata.operation_name': 'AssessmentGroup',
        'operation_metadata.operation_adversary': 'Campaign',
        'attack_metadata.technique_id': 'MitreID',
        'attack_metadata.technique_name': 'Method',
        'attack_metadata.tactic': 'Phase',
        'ability_metadata.ability_name': 'Objective',
        'command': 'Command',
        'output.stdout': 'Outcome Notes',
        'status': 'Status',
        'agent_metadata.username': 'TargetAssets',
        'executor': 'Attack Vector',
        'pid': 'Privileges Required',
        'delegated_timestamp': 'Start Time',
        'collected_timestamp': 'Stop Time',
        'finished_timestamp': 'Detection Time',
        'agent_metadata.host': 'SourceIps',
        'platform': 'Tags'
    }

    vectr_headers = [
        'AssessmentGroup', 'Campaign', 'Phase', 'Variant', 'MitreID', 'CapecId', 'Method', 'Status',
        'Outcome','Outcome Path', 'Alert Severity', 'Alert Triggered', 'Activity Logged', 'Outcome Notes',
        'Detection Recommendations', 'SourceIps', 'TargetAssets', 'ExpectedDetectionLayers',
        'DetectingTools', 'Start Time', 'Start Time Epoch', 'Stop Time', 'Stop Time Epoch',
        'Detection Time', 'Detection Time Epoch', 'Organizations', 'Tags', 'Objective',
        'Command', 'References', 'Liklihood', 'Risk', 'Internal/External', 'Stealth',
        'Attack Vector', 'Attack Complexity', 'Privileges Required', 'Attacker Tools'
    ]

    phase_map = {
        'build-capabilities': 'Resource Development',
        'collection': 'Collection',
        'command-and-control': 'Command & Control',
        'credential-access': 'Credential Access',
        'defense-evasion': 'Defense Evasion',
        'discovery': 'Discovery',
        'execution': 'Execution',
        'exfiltration': 'Exfiltration',
        'impact': 'Impact',
        'initial-access': 'Initial Access',
        'lateral-movement': 'Lateral Movement',
        'multiple': 'Impact',
        'persistence': 'Persistence',
        'privilege-escalation': 'Privilege Escalation',
        'reconnaissance': 'Reconnaissance',
        'technical-information-gathering': 'Reconnaissance'
    }

    # Load MITRE CSV
    mitre_data = {}
    if Path(mitre_csv_path).exists():
        with open(mitre_csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                technique_id = row['id'].strip()
                mitre_data[technique_id] = {
                    'detection': row['detection'],
                    'url': row['url'],
                    'data_sources': row['data sources']
                }

    # Load and flatten JSON
    with open(input_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    flat_data = [flatten_json(entry) for entry in data]

    # Transform data
    csv_rows = []
    for entry in flat_data:
        row = {header: '' for header in vectr_headers}
        for source_field, target_field in field_map.items():
            if source_field in entry:
                row[target_field] = entry[source_field]

        if row['Phase'] in phase_map:
            row['Phase'] = phase_map[row['Phase']]
        row['Variant'] = row['Objective']

        row['Start Time Epoch'] = iso_to_epoch(row['Start Time']) if row['Start Time'] else ''
        row['Stop Time Epoch'] = iso_to_epoch(row['Stop Time']) if row['Stop Time'] else ''
        row['Detection Time Epoch'] = iso_to_epoch(row['Detection Time']) if row['Detection Time'] else ''

        row['Status'] = 'Completed'
        row['Outcome'] = 'Detected' if row['Outcome Notes'] else 'Not Detected'

        row['Organizations'] = row['Organizations'] or 'Internal'
        row['Internal/External'] = 'Internal'

        row['Alert Triggered'] = 'TBD'
        row['Activity Logged'] = 'TBD'
        row['Alert Severity'] = 'TBD'

        row['Privileges Required'] = str(row['Privileges Required']) if row['Privileges Required'] else ''

        mitre_id = row['MitreID']
        if mitre_id and mitre_id in mitre_data:
            mitre_info = mitre_data[mitre_id]
            detection_recommendations = []
            if mitre_info['detection']:
                detection_recommendations.append(mitre_info['detection'])
            if mitre_info['data_sources']:
                detection_recommendations.append(f"Monitor these data sources: {mitre_info['data_sources']}")
            row['Detection Recommendations'] = "\n".join(detection_recommendations)
            row['References'] = mitre_info['url']

        csv_rows.append(row)

    # Write output
    with open(output_csv_path, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=vectr_headers)
        writer.writeheader()
        for row in csv_rows:
            writer.writerow(row)

    print(f"Vectr-compatible CSV written to: {Path(output_csv_path).resolve()}")
