import boto3
import botocore
# import jsonschema
import json
import traceback

from requests.utils import quote
from botocore.exceptions import ClientError

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name, handle_common_errors

eh = ExtensionHandler()

cognito = boto3.client("cognito")
def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)
        prev_state = event.get("prev_state")
        cdef = event.get("component_def")
        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        
        identity_pool_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname, max_chars=80)
        
        allow_unauthenticated_identities = cdef.get("allow_unauthenticated_identities", True)
        allow_classic_flow = cdef.get("allow_classic_flow") or False
        supported_login_providers = remove_none_attributes({
            "graph.facebook.com": cdef.get("facebook_app_id"),
            "accounts.google.com": cdef.get("google_app_id"),
            "www.amazon.com": cdef.get("amazon_app_id"),
            "api.twitter.com": cdef.get("twitter_app_id"),
            "www.digits.com": cdef.get("digits_app_id")
        }) or None

        developer_provider_name = cdef.get("developer_provider_name")
        oidc_provider_arns = cdef.get("oidc_provider_arns")
        cognito_identity_providers = cdef.get("cognito_identity_providers")

        saml_provider_arns = cdef.get("saml_provider_arns")
        tags = cdef.get("tags") or {}

        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            old_queue_name = None
            old_queue_url = None
            try:
                old_queue_name = prev_state["props"]["name"]
                old_queue_url = prev_state["props"]["url"]
            except:
                pass
            
            eh.add_op("get_queue_url")
            if old_queue_name and queue_name != old_queue_name:
                eh.add_op("delete_queue", {"url":old_queue_url, "only_delete": False})

        elif event.get("op") == "delete":
            eh.add_op("delete_queue", {"url":prev_state.get("props", {}).get("url"), "only_delete": True})
        
        attributes = remove_none_attributes({
            "IdentityPoolName": identity_pool_name,
            "AllowUnauthenticatedIdentities": allow_unauthenticated_identities,
            "AllowClassicFlow": allow_classic_flow,
            "SupportedLoginProviders": supported_login_providers,
            "DeveloperProviderName": developer_provider_name,
            "OpenIdConnectProviderARNs": oidc_provider_arns,
            "CognitoIdentityProviders": cognito_identity_providers,
            "SamlProviderARNs": saml_provider_arns,
            "IdentityPoolTags": tags
        })

        attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        print(attributes)

        get_queue_url(queue_name, account_number, region)
        get_queue(attributes, tags)
        create_identity_pool(attributes, account_number, region)
        remove_tags()
        add_tags()
        delete_identity_pool()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_queue_url")
def get_queue_url(queue_name, account_number, region):
    try:
        response = cognito.get_queue_url(QueueName=queue_name)
        eh.add_state({"queue_url": response["QueueUrl"]})
        eh.add_op("get_queue")

        eh.add_props({
            "arn": gen_cognito_queue_arn(queue_name, account_number, region),
            "url": response["QueueUrl"],
            "name": queue_name
        })

        eh.add_links({
            "Queue": gen_cognito_queue_link(region, response["QueueUrl"])
        })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue":
            eh.add_op("create_queue")
        else:
            handle_common_errors(e, eh, "Get Queue Url Failure", 0)

@ext(handler=eh, op="get_identity_pool")
def get_identity_pool(attributes, identity_pool_id):
    queue_url = eh.state["queue_url"]

    try:
        response = cognito.describe_identity_pool(
            IdentityPoolId=identity_pool_id
        )
        eh.add_log("Got Identity Pool", response)
        current_attributes = response["Attributes"]
        print(f"current_attributes = {current_attributes}")
        print(f"attributes = {attributes}")
        for k,v in attributes.items():
            if str(current_attributes.get(k)).lower() != str(v).lower():
                eh.add_op("set_queue_attributes")
                print(k)
                print(v)
                print(type(k))
                print(type(v))
                break

        if not eh.ops.get("set_queue_attributes"):
            eh.add_log("Nothing to do. Exiting", {"current_attributes": current_attributes, "desired_attributes": attributes})

    except ClientError as e:
        if e.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue":
            eh.add_op("create_queue")
        else:
            handle_common_errors(e, eh, "Get Queue Attributes Failure", 0)

    try:
        tags_response = cognito.list_queue_tags(QueueUrl=queue_url)
        current_tags = tags_response.get("Tags") or {}
    except ClientError as e:
        handle_common_errors(e, eh, "List Queue Tags Error", 10)

    if tags != current_tags:
        remove_tags = [k for k in current_tags.keys() if k not in tags]
        add_tags = {k:v for k,v in tags.items() if k not in current_tags.keys()}
        if remove_tags:
            eh.add_op("remove_tags", remove_tags)
        if add_tags:
            eh.add_op("add_tags", add_tags)


@ext(handler=eh, op="create_identity_pool")
def create_identity_pool(attributes, account_number, region):
    try:
        response = cognito.create_identity_pool(**attributes)
        eh.add_log("Created Identity Pool", response)
        eh.add_props({
            "name": response['IdentityPoolName'],
            "id": response["IdentityPoolId"],
            "arn": gen_cognito_identity_pool_arn(response['IdentityPoolName'], account_number, region)
        })

        eh.add_links({
            "Identity Pool": gen_cognito_identity_pool_link(region, response["QueueUrl"])
        })

    except ClientError as e:
        handle_common_errors(e, eh, "Error Creating Identity Pool", 20, [
            "InvalidParameterException", "NotAuthorizedException"
        ])


@ext(handler=eh, op="add_tags")
def add_tags():
    tags = eh.ops.get("add_tags")
    arn = eh.props["arn"]
    try:
        response = cognito.tag_resource(
            ResourceArn=arn,
            Tags=tags
        )
        eh.add_log("Tags Added", response)

    except ClientError as e:
        handle_common_errors(e, eh, "Error Adding Tags", progress=90)
        

@ext(handler=eh, op="remove_tags")
def remove_tags():
    remove_tags = eh.ops['remove_tags']
    arn = eh.props["arn"]

    try:
        cognito.untag_queue(
            ResourceArn=arn,
            TagKeys=remove_tags
        )
        eh.add_log("Tags Removed", {"tags_removed": remove_tags})

    except ClientError as e:
        handle_common_errors(e, eh, "Error Removing Tags", progress=80)

def gen_cognito_identity_pool_arn(queue_name, account_number, region):
    return f"arn:aws:cognito:{region}:{account_number}:{queue_name}"

def gen_cognito_identity_pool_link(region, queue_url):
    return f"https://{region}.console.aws.amazon.com/cognito/v2/home?region={region}#/queues/{quote(queue_url, safe='')}"

@ext(handler=eh, op="delete_identity_pool")
def delete_identity_pool():
    op_info = eh.ops['delete_identity_pool']
    identity_pool_id = op_info['id']
    only_delete = op_info.get("only_delete")

    try:
        cognito.delete_identity_pool(
            IdentityPoolId = identity_pool_id
        )
        eh.add_log("Identity Pool Deleted", {"identity_pool_id": identity_pool_id})

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            eh.add_log("Old Identity Pool Doesn't Exist", {"identity_pool_id": identity_pool_id})
        else:
            handle_common_errors(e, eh, "Error Deleting Identity Pool", progress=(95 if only_delete else 20))
