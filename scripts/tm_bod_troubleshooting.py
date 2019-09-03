#!/usr/bin/env python

"""
Script to provide BOD failure info for trustymail reports.

This script is designed to take the trustymail_results.csv file for a given
organization's report and provide more granular information about why domains
are failing. Additional information is given for DMARC and RUA URL failures
because the checks are more involved than single value true/false checks.
"""

import csv
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <trustymail Report CSV file>")
    exit(-1)

csv_file = sys.argv[1]

bod_rua_url = "mailto:reports@dmarc.cyber.dhs.gov"

count_values = {
    "total_domains": 0,
    "domains_checked": 0,
    "domains_skipped": 0,
    "smtp_valid": 0,
    "smtp_invalid": 0,
    "spf_covered": 0,
    "spf_not_covered": 0,
    "no_weak_crypto": 0,
    "has_weak_crypto": 0,
    "dmarc_valid": 0,
    "dmarc_invalid": 0,
    "bod_compliant": 0,
    "bod_failed": 0,
}

failed_domains = {
    "invalid_dmarc": {
        "title": "Domains With Invalid DMARC Configurations ::",
        "domains": [],
    },
    "invalid_rua": {
        "title": f'Domains Missing RUA URL "{bod_rua_url}" ::',
        "domains": [],
    },
}

with open(csv_file, "r") as f:
    tmreader = csv.DictReader(f)
    for row in tmreader:
        for k, v in row.items():
            if v is None:
                continue
            if v.strip().lower() == "true":
                row[k] = True
            elif v.strip().lower() == "false":
                row[k] = False

        count_values["total_domains"] += 1

        valid_dmarc = row["Valid DMARC"] or row["Valid DMARC Record on Base Domain"]
        valid_dmarc_policy_reject = valid_dmarc and (row["DMARC Policy"] == "reject")
        valid_dmarc_subdomain_policy_reject = valid_dmarc and (
            not row["Domain Is Base Domain"]
            or (row["DMARC Subdomain Policy"] == "reject")
        )
        valid_dmarc_policy_pct = valid_dmarc and (
            row["DMARC Policy Percentage"] == "100"
        )
        valid_dmarc_policy_of_reject = (
            valid_dmarc_policy_reject
            and valid_dmarc_subdomain_policy_reject
            and valid_dmarc_policy_pct
        )

        if row["Domain Is Base Domain"]:
            spf_covered = row["Valid SPF"]
        else:
            spf_covered = row["Valid SPF"] or (
                (not row["SPF Record"]) and valid_dmarc_policy_of_reject
            )

        valid_dmarc_bod1801_rua_url = False
        if valid_dmarc:
            if bod_rua_url in [
                u.strip().lower() for u in row["DMARC Aggregate Report URIs"].split(",")
            ]:
                valid_dmarc_bod1801_rua_url = True

        bod_1801_compliant = (
            spf_covered
            and (not row["Domain Supports Weak Crypto"])
            and valid_dmarc_policy_of_reject
            and valid_dmarc_bod1801_rua_url
        )

        if row["Domain Is Base Domain"] or (
            not row["Domain Is Base Domain"] and row["Domain Supports SMTP"]
        ):
            count_values["domains_checked"] += 1
            if (row["Domain Supports SMTP"] and row["Domain Supports STARTTLS"]) or (
                not row["Domain Supports SMTP"]
            ):
                count_values["smtp_valid"] += 1
                if spf_covered:
                    count_values["spf_covered"] += 1
                    if not row["Domain Supports Weak Crypto"]:
                        count_values["no_weak_crypto"] += 1
                        if valid_dmarc_policy_of_reject:
                            count_values["dmarc_valid"] += 1
                            if valid_dmarc_bod1801_rua_url:
                                count_values["bod_compliant"] += 1
                            else:
                                count_values["bod_failed"] += 1
                                message = ["\tRUA URLs:"]
                                for url in [
                                    u.strip().lower()
                                    for u in row["DMARC Aggregate Report URIs"].split(
                                        ","
                                    )
                                ]:
                                    message.append(f"\t\t{url}")
                                failed_domains["invalid_rua"]["domains"].append(
                                    {"domain": row["Domain"], "message": message}
                                )
                        else:
                            count_values["dmarc_invalid"] += 1
                            message = [
                                f"\tBase Domain: {row['Domain Is Base Domain']}",
                                f"\tValid DMARC: {valid_dmarc}",
                                f"\tDMARC Policy: \"{row['DMARC Policy']}\"",
                                f"\tDMARC Subdomain Policy: \"{row['DMARC Subdomain Policy']}\"",
                                f"\tDMARC Policy Percentage: {row['DMARC Policy Percentage']}",
                                f"\tConditions (Must be True):",
                                f'\t\tValid DMARC and Policy == "reject": {valid_dmarc_policy_reject}',
                                f'\t\tValid DMARC and (not Base Domain or Subdomain Policy == "reject"): {valid_dmarc_subdomain_policy_reject}',
                                f"\t\tValid DMARC and Policy Percentage == 100: {valid_dmarc_policy_pct}",
                            ]
                            failed_domains["invalid_dmarc"]["domains"].append(
                                {"domain": row["Domain"], "message": message}
                            )
                    else:
                        count_values["has_weak_crypto"] += 1
                else:
                    count_values["spf_not_covered"] += 1
            else:
                count_values["smtp_invalid"] += 1
        else:
            count_values["domains_skipped"] += 1

for k, v in failed_domains.items():
    if len(v["domains"]) == 0:
        continue
    print(v["title"])
    for domain in v["domains"]:
        print(f"\t{domain['domain']}")
        for line in domain["message"]:
            print(f"\t{line}")
    print()

for k, v in count_values.items():
    print(f"{k} :: {v}")
