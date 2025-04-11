import requests
from dotenv import dotenv_values

env_config = dotenv_values(".env")
api_key = f"VEC1 {env_config.get('API_KEY')}"
vectr_gql_url = env_config.get("VECTR_GQL_URL")

headers = {
    "Authorization": api_key,
    "Content-Type": "application/json"
}

query = """
query {
  databases {
    id
    name
  }
}
"""

response = requests.post(vectr_gql_url, headers=headers, json={"query": query}, verify=False)
print(response.json())
