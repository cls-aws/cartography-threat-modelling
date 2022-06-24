import logging
from typing import Dict
from typing import List

import boto3
import botocore.exceptions
import neo4j

from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_inspector_findings_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    try:
        client = boto3_session.client('inspector2', region_name=region)
        paginator = client.get_paginator('list_findings')
        findings: List[Dict] = []
        for page in paginator.paginate(filterCriteria={
                'findingStatus': [
                    {
                        'comparison': 'EQUALS',
                        'value': 'ACTIVE'
                    },
                ],
                'findingType': [
                    {
                        'comparison': 'EQUALS',
                        'value': 'PACKAGE_VULNERABILITY'
                    },
                ],
            }):
            findings.extend(page['findings'])
    except botocore.exceptions.ClientError:
        logger.warning(f"Cant get findings.")

    return findings

@timeit
# Currently only retrieving PACKAGE_VULNERABILITY records (filtered through boto client)
def load_inspector_findings_data(
    neo4j_session: neo4j.Session, findings: List[Dict], region: str, aws_update_tag: int,
) -> None:
    for finding in findings:
        if finding['type'] == 'PACKAGE_VULNERABILITY':
            _load_package_vulnerability_finding(neo4j_session, finding, aws_update_tag)
        elif finding['type'] == 'NETWORK_REACHABILITY':
            _load_network_reachability_finding(neo4j_session, finding, aws_update_tag)
        else:
            print("not able to determine finding type - something went wrong")

@timeit
def _load_package_vulnerability_finding(neo4j_session: neo4j.Session, finding: Dict, aws_update_tag: int) -> None:
    ingest_findings = """
    MERGE (finding:InspectorFinding{id: {Arn}})
    ON CREATE SET finding.firstseen = timestamp(),
    finding.arn = {Arn}
    SET finding.description = {FindingDescription},
    finding.severity = {FindingSeverity},
    finding.first_observed_at = {FirstObservedAtTime},
    finding.lastupdated = {aws_update_tag},
    finding.cvss_score = {CvssScore},
    finding.inspector_score = {InspectorScore}
    WITH finding
    MATCH (ecc:EC2Instance{id: {InstanceId}})
    MERGE (ecc)-[r:HAS_VULNERABILITY]->(finding)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    MERGE (cs:CVSSScore{name: {CvssScore}})
    ON CREATE SET cs.firstseen = timestamp()
    MERGE (finding)-[t:HAS_CVSS_SCORE]->(cs)
    MERGE (is:InspectorScore)
    """
 
    neo4j_session.run(
        ingest_findings,
        Arn=finding['findingArn'],
        FindingDescription=finding['description'],
        FindingSeverity=finding['severity'],
        FirstObservedAtTime=finding['firstObservedAt'],
        CvssScore="0",
#        CvssScore=finding['packageVulnerabilityDetails']['cvss'][0]['baseScore'],
        InspectorScore=finding['inspectorScore'],
        InstanceId=finding['resources'][0].get('id'),
        aws_update_tag=aws_update_tag,
        )

def _load_network_reachability_finding(neo4j_session: neo4j.Session, finding: Dict, aws_update_tag: int) -> None:
    pass


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_inspector2_findings_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_inspector_findings(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, region: str,
    current_aws_account_id: str, aws_update_tag: int,
) -> None:
    data = get_inspector_findings_data(boto3_session, region)
    load_inspector_findings_data(neo4j_session, data, region, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    
    # hardcode test region
    regions = {'ap-southeast-2'}
    
    for region in regions:
        logger.info("Syncing Inspector findings for region '%s' in account '%s'.", region, current_aws_account_id)
        sync_inspector_findings(neo4j_session, boto3_session, region, current_aws_account_id, update_tag)
    #cleanup(neo4j_session, common_job_parameters)

