# Enhanced scanner.py with Rich CLI, Slack alerts, HTML/Markdown reports, and secret scanning
import boto3
import argparse
import json
import re
import os
from botocore.exceptions import ClientError
from rich import print
from rich.table import Table
from slack_sdk.webhook import WebhookClient
from jinja2 import Template

# Constants
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        print("[yellow] No Slack webhook URL found in environment. Skipping alert.")
        return
    webhook = WebhookClient(SLACK_WEBHOOK_URL)
    response = webhook.send(text=message)
    if response.status_code == 200:
        print("[green] Slack alert sent successfully.")

def check_s3_public_buckets():
    s3 = boto3.client('s3')
    public_buckets = []

    for bucket in s3.list_buckets()['Buckets']:
        name = bucket['Name']
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl['Grants']:
            if grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public_buckets.append(name)
                break
    return public_buckets

def check_open_security_groups():
    ec2 = boto3.client('ec2')
    insecure_sgs = []

    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    insecure_sgs.append({
                        'GroupId': sg['GroupId'],
                        'Port': perm.get('FromPort'),
                        'Protocol': perm.get('IpProtocol')
                    })
    return insecure_sgs

def check_unencrypted_ebs_volumes():
    ec2 = boto3.client('ec2')
    unencrypted = []

    for volume in ec2.describe_volumes()['Volumes']:
        if not volume['Encrypted']:
            unencrypted.append(volume['VolumeId'])
    return unencrypted

def scan_for_secrets_in_s3():
    s3 = boto3.client('s3')
    findings = []

    for bucket in s3.list_buckets()['Buckets']:
        name = bucket['Name']
        try:
            objects = s3.list_objects_v2(Bucket=name).get('Contents', [])
            for obj in objects:
                key = obj['Key']
                if not key.endswith(('.txt', '.sh', '.py', '.json')): continue
                body = s3.get_object(Bucket=name, Key=key)['Body'].read().decode(errors='ignore')
                if re.search(r'AKIA[0-9A-Z]{16}', body):
                    findings.append({'Bucket': name, 'Key': key})
        except Exception:
            continue
    return findings

def generate_markdown(report):
    md = "# AWS Misconfiguration Scan Report\n\n"
    for k, v in report.items():
        md += f"## {k.replace('_', ' ').title()}\n"
        if isinstance(v, list) and v:
            for item in v:
                md += f"- {item}\n"
        elif not v:
            md += "- No issues found.\n"
    with open("reports/scan_report.md", "w") as f:
        f.write(md)

def display_rich_output(report):
    for key, items in report.items():
        table = Table(title=key.replace('_', ' ').title())
        if isinstance(items, list) and items:
            if isinstance(items[0], dict):
                for col in items[0].keys():
                    table.add_column(col)
                for item in items:
                    table.add_row(*[str(item[col]) for col in item])
            else:
                table.add_column("Resource")
                for item in items:
                    table.add_row(item)
        else:
            table.add_column("Status")
            table.add_row("No issues found.")
        print(table)

def main(profile, region):
    boto3.setup_default_session(profile_name=profile, region_name=region)
    print("[bold cyan]\n🔍 Starting AWS Misconfiguration Scanner...\n")

    report = {
        "public_s3_buckets": check_s3_public_buckets(),
        "open_security_groups": check_open_security_groups(),
        "unencrypted_ebs_volumes": check_unencrypted_ebs_volumes(),
        "secrets_in_s3": scan_for_secrets_in_s3()
    }

    display_rich_output(report)
    generate_markdown(report)

    with open("reports/scan_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n Scan complete. Reports saved to 'reports/' folder.")

    # Optional alert
    if any(report.values()):
        send_slack_alert("🚨 AWS Misconfiguration Scanner found issues. Review the latest report.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan AWS for misconfigurations")
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', required=True, help='AWS region to scan')
    args = parser.parse_args()
    main(args.profile, args.region)
