import sys
import json
import requests


# Gets the slug of the organization that the SEMGREP_API_WEB_TOKEN has access to.
def get_deployment_slug(token):
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    }

    r = requests.get("https://semgrep.dev/api/v1/deployments", headers=headers)
    if r.status_code != 200:
        sys.exit(f"Getting org details failed: {r.text}")
    data = json.loads(r.text)
    slug_name = data["deployments"][0].get("slug")
    return slug_name


# Gets list of all the projects under the Semgrep organization with given slug.
def get_projects(token, slug):

    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    }
    params = {"page_size": 3000}

    r = requests.get(
        "https://semgrep.dev/api/v1/deployments/" + slug + "/projects?page=0",
        params=params,
        headers=headers,
    )
    if r.status_code != 200:
        sys.exit(f"Getting list of projects failed: {r.text}")

    response_text = json.loads(r.text)
    return response_text["projects"]


# Gets the findings for one project.
def get_project_findings(token, slug, project_name):
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    }
    params = {"page_size": 3000, "repos": project_name}
    # r = requests.get('https://semgrep.dev/api/v1/deployments/' + slug_name + '/findings?repos='+repo,params=params, headers=headers)
    r = requests.get(
        "https://semgrep.dev/api/v1/deployments/" + slug + "/findings",
        params=params,
        headers=headers,
    )
    if r.status_code != 200:
        sys.exit(f"Getting findings for project failed: {r.text}")
    findings = json.loads(r.text)
    return findings["findings"]
