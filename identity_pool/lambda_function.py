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

cognito = boto3.client("cognito-identity")
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
        
        identity_pool_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname, max_chars=64)
        
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

        if :


        cognito_provider_name = cdef.get("cognito_provider_name")
        cognito_client_id = cdef.get("cognito_client_id")
        
        if not cognito_identity_providers:
            if cdef.get("user_pool_client"):
                user_pool_client = cdef.get("user_pool_client")
                user_pool_client_region = user_pool_client.get("user_pool_id").split("_")[0]
                cognito_identity_providers = [{
                    "provider_name": "",
                    "provider_client_id": cognito_client_id
                }]
            cognito_identity_providers = [
                remove_none_attributes({
                    "ProviderName": cognito_provider_name,
                    "ClientId": cognito_client_id,
                    "ServerSideTokenCheck": False,
                })
            ]

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

        get_identity_pool(attributes, identity_pool_id)
        create_identity_pool(attributes, account_number, region)
        update_identity_pool(attributes, account_number, region)
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

@ext(handler=eh, op="get_identity_pool")
def get_identity_pool(attributes, identity_pool_id):
    tags = attributes.get("IdentityPoolTags") or {}

    try:
        response = cognito.describe_identity_pool(
            IdentityPoolId=identity_pool_id
        )

        current_tags = response.pop("IdentityPoolTags")
        eh.add_log("Got Identity Pool", response)
        print(f"current_attributes = {response}")
        print(f"attributes = {attributes}")
        for k,v in attributes.items():
            if str(current_attributes.get(k)).lower() != str(v).lower():
                eh.add_op("update_identity_pool")
                print(k)
                print(v)
                print(type(k))
                print(type(v))
                break

        if tags != current_tags:
            remove_tags = [k for k in current_tags.keys() if k not in tags]
            add_tags = {k:v for k,v in tags.items() if v != current_tags.get(k)}
            if remove_tags:
                eh.add_op("remove_tags", remove_tags)
            if add_tags:
                eh.add_op("add_tags", add_tags)

        if not eh.ops.get("set_queue_attributes"):
            eh.add_log("Nothing to do. Exiting", {"current_attributes": current_attributes, "desired_attributes": attributes})


    except ClientError as e:
        if e.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue":
            eh.add_op("create_queue")
        else:
            handle_common_errors(e, eh, "Get Queue Attributes Failure", 0)


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

@ext(handler=eh, op="update_identity_pool")
def update_identity_pool(attributes, account_number, region):
    try:
        response = cognito.update_identity_pool(**attributes)
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
