from gql import Client, gql
from gql.dsl import DSLQuery, DSLSchema, dsl_gql
from gql.transport.requests import RequestsHTTPTransport
from pydantic import BaseModel
from typing import Dict
from models import Campaign, TestCase

# REMOVE ME
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VectrGQLConnParams(BaseModel):
    api_key: str
    vectr_gql_url: str


class TestCaseGQLInput(BaseModel):
    testCaseData: TestCase


def get_client(connection_params: VectrGQLConnParams):
    transport = RequestsHTTPTransport(
        url=connection_params.vectr_gql_url, verify=False, retries=1,
        headers={"Authorization": "VEC1 " + connection_params.api_key}
    )

    return Client(transport=transport, fetch_schema_from_transport=True)


def api_can_use_new_outcome_paths(connection_params: VectrGQLConnParams) -> bool:
    return False  # Always false


def create_assessment(connection_params: VectrGQLConnParams,
                      db: str,
                      org_id: str,
                      assessment_name: str) -> Dict[str, dict]:
    client = get_client(connection_params)
    assessment_mutation = gql(
        """
        mutation ($input: CreateAssessmentInput!) {
          assessment {
            create(input: $input) {
              assessments {
                id, name, description, createTime
              }
            }
          }
        }
        """
    )

    assessment_vars = {
        "input": {
            "db": db,
            "assessmentData": [
                {
                    "name": assessment_name,
                    "organizationIds": [org_id]
                }
            ]
        }
    }

    assessments = {}

    result = client.execute(assessment_mutation, variable_values=assessment_vars)
    if "assessment" in result.keys():
        assessment_type_res = result["assessment"]
        if "create" in assessment_type_res:
            create_res = assessment_type_res["create"]
            if "assessments" in create_res:
                assessments_created = create_res["assessments"]

                for assessment in assessments_created:
                    assessments[assessment["name"]] = {"id": assessment["id"], "name": assessment["name"]}

    print(assessments)

    return assessments


def create_campaigns(connection_params: VectrGQLConnParams,
                     db: str,
                     org_id: str,
                     campaigns: Dict[str, Campaign],
                     parent_assessment_id: str) -> Dict[str, dict]:
    client = get_client(connection_params)
    campaign_mutation = gql(
        """
        mutation ($input: CreateCampaignInput!) {
          campaign {
            create(input: $input) {
              campaigns {
                id, name, createTime
              }
            }
          }
        }
        """
    )

    campaign_data = []
    for campaign_name in campaigns.keys():
        campaign_data.append({
            "name": campaign_name,
            "organizationIds": [org_id]
        })

    campaign_vars = {
        "input": {
            "db": db,
            "assessmentId": parent_assessment_id,
            "campaignData": campaign_data
        }
    }

    campaigns = {}

    result = client.execute(campaign_mutation, variable_values=campaign_vars)

    print(result)
    if "campaign" in result.keys():
        campaign_type_res = result["campaign"]
        if "create" in campaign_type_res:
            create_res = campaign_type_res["create"]
            if "campaigns" in create_res:
                campaigns_created = create_res["campaigns"]

                for campaign in campaigns_created:
                    campaigns[campaign["name"]] = {"id": campaign["id"], "name": campaign["name"]}

    return campaigns


def create_test_cases(connection_params: VectrGQLConnParams,
                      db: str,
                      campaign_id: str,
                      test_cases: Dict[str, TestCase],
                      api_has_outcome_paths: bool) -> Dict[str, dict]:
    client = get_client(connection_params)
    test_case_mutation = gql(
        """
        mutation ($input: CreateTestCaseAndTemplateMatchByNameInput!) {
          testCase {
            createWithTemplateMatchByName(input: $input) {
              testCases {
                id, name
              }
            }
          }
        }
        """
    )

    test_case_data = []
    existing_names = set()
    for idx, test_case in enumerate(test_cases):
        test_case_dict = dict(test_case)
        base_name = test_case_dict.get("name", f"Unnamed-{idx}").strip()
        new_name = base_name
        while new_name in existing_names:
            new_name = f"{base_name}-{idx}"
        test_case_dict["name"] = new_name
        existing_names.add(new_name)

        if 'outcomePath' in test_case_dict:
            del test_case_dict['outcomePath']

        test_case_data.append({
            "testCaseData": test_case_dict
        })

    test_case_vars = {
        "input": {
            "db": db,
            "campaignId": campaign_id,
            "createTestCaseInputs": test_case_data
        }
    }

    test_cases = {}

    result = client.execute(test_case_mutation, variable_values=test_case_vars)

    print(result)
    if "testCase" in result.keys():
        test_case_type_res = result["testCase"]
        if "create" in test_case_type_res:
            create_res = test_case_type_res["create"]
            if "testCases" in create_res:
                test_cases_created = create_res["testCases"]

                for test_case in test_cases_created:
                    test_cases[test_case["name"]] = {"id": test_case["id"], "name": test_case["name"]}

    return test_cases


def get_org_id_for_campaign_and_assessment_data(connection_params: VectrGQLConnParams, org_name: str) -> str:
    client = get_client(connection_params)

    org_query = gql(
        """
        query($nameVar: String) {
          organizations(filter: {name: {eq:  $nameVar}}) {
            nodes {
              id, name
            }
          }
        }
    """
    )

    org_vars = {"nameVar": org_name}

    result = client.execute(org_query, variable_values=org_vars)

    if "organizations" in result.keys():
        organizations_type_res = result["organizations"]
        if "nodes" in organizations_type_res:
            nodes_res = organizations_type_res["nodes"]
            if nodes_res:
                return nodes_res[0]["id"]

    raise RuntimeError("couldn't find org name. create in VECTR first")
