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

cognito = boto3.client("cognito-idp")
def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)
        prev_state = event.get("prev_state") or {}
        cdef = event.get("component_def")
        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        
        client_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname, max_chars=100)
        user_pool_id = cdef.get("user_pool_id")
        if not user_pool_id:
            raise Exception(f"Must pass user_pool_id")
        if prev_state and prev_state.get("props", {}).get("user_pool_id") != user_pool_id:
            eh.add_log("Cannot Change User Pool ID")
            raise Exception(f"Cannot Change User Pool ID")

        generate_secret = cdef.get("generate_secret", True)

        access_token_expiration_minutes = cdef.get("access_token_expiration_minutes", 60)
        refresh_token_expiration_minutes = cdef.get("refresh_token_expiration_minutes", 43200)
        refresh_token_unit = "minutes"
        id_token_expiration_minutes = cdef.get("id_token_expiration_minutes", 60)
        if refresh_token_expiration_minutes % (60*24) == 0:
            refresh_token_expiration_minutes = int(refresh_token_expiration_minutes /(60*24))
            refresh_token_unit = "days"

        read_attributes = cdef.get("read_attributes") or None
        write_attributes = cdef.get("write_attributes") or None

        auth_flows = cdef.get("auth_flows") or ["ALLOW_CUSTOM_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
        supported_identity_providers = cdef.get("supported_identity_providers") or ["COGNITO"]

        callback_urls = cdef.get("callback_urls") or None
        logout_urls = cdef.get("logout_urls") or None
        default_redirect_uri = cdef.get("default_redirect_uri")

        oauth_flows = cdef.get("oauth_flows") or ["client_credentials"]
        oauth_scopes = cdef.get("oauth_scopes")

        prevent_user_existence_errors = cdef.get("prevent_user_existence_errors") or "ENABLED"
        token_revocation = cdef.get("token_revocation") or False
        # enable_propagate_additional_user_context_data = cdef.get("enable_propagate_additional_user_context_data") or False

        
        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass

        elif event.get("op") == "upsert":
            if prev_state.get("props", {}).get("id"):
                eh.add_op("get_user_pool_client")
                eh.add_state({
                    "user_pool_client_id": prev_state.get("props", {}).get("id")
                })
            else:
                eh.add_op("create_user_pool_client")

            # if domain:
            #     eh.add_op("get_domain")
            # elif prev_state.get("props", {}).get("domain"):
            #     eh.add_op("delete_domain", {"domain": domain})

        elif event.get("op") == "delete":
            eh.add_op("delete_user_pool_client", {
                "id":prev_state.get("props", {}).get("id"), 
                "user_pool_id": user_pool_id
            })
        
        attributes = remove_none_attributes({
            "UserPoolId": user_pool_id,
            "ClientName": client_name,
            "GenerateSecret": generate_secret,
            "RefreshTokenValidity": refresh_token_expiration_minutes,
            "AccessTokenValidity": access_token_expiration_minutes,
            "IdTokenValidity": id_token_expiration_minutes,
            "TokenValidityUnits": {
                "AccessToken": "minutes",
                "RefreshToken": refresh_token_unit,
                "IdToken": "minutes"
            },
            "ReadAttributes": read_attributes,
            "WriteAttributes": write_attributes,
            "ExplicitAuthFlows": auth_flows,
            "SupportedIdentityProviders": supported_identity_providers,
            "CallbackURLs": callback_urls,
            "LogoutURLs": logout_urls,
            "DefaultRedirectURI": default_redirect_uri,
            "AllowedOAuthFlows": oauth_flows,
            "AllowedOAuthScopes": oauth_scopes,
            "PreventUserExistenceErrors": prevent_user_existence_errors,
            "EnableTokenRevocation": token_revocation,
            # "EnablePropagateAdditionalUserContextData": enable_propagate_additional_user_context_data
        })

        # attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        print(attributes)

        get_user_pool_client(attributes, cdef, region, user_pool_id)
        create_user_pool_client(attributes, account_number, region)
        update_user_pool_client(attributes, account_number, region)
        delete_user_pool_client()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_user_pool_client")
def get_user_pool_client(attributes, cdef, region, user_pool_id):
    user_pool_client_id = eh.state["user_pool_client_id"]
    try:
        response = cognito.describe_user_pool_client(
            UserPoolId=user_pool_id,
            ClientId=user_pool_client_id
        )

        user_pool_client = response["UserPoolClient"]
        eh.add_log("Got User Pool Client", response)
        print(f"current_attributes = {user_pool_client}")

        #Loop through the attributes and compare them to the current attributes
        #If they are different, then update the user pool
        for k,v in attributes.items():

            #If we are working with the password policy, remove temp_valid_days from comparison
            if user_pool_client.get(k) != v:
                eh.add_op("update_user_pool_client", {"id": user_pool_client_id, "attributes": attributes})
                print(k)
                print(v)
                print(type(k))
                print(type(v))
                break

        eh.add_props({
            "name": user_pool_client['ClientName'],
            "id": user_pool_client["ClientId"],
            "secret": user_pool_client["ClientSecret"],
            "user_pool_id": user_pool_client["UserPoolId"]
        })

        eh.add_links({
            "User Pool Client": gen_cognito_user_pool_client_link(region, user_pool_client["UserPoolId"])
        })

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            eh.add_op("create_user_pool_client")
        else:
            handle_common_errors(e, eh, "Get User Pool Client Failure", 0)


@ext(handler=eh, op="create_user_pool_client")
def create_user_pool_client(attributes, account_number, region):
    try:
        response = cognito.create_user_pool_client(**attributes)
        user_pool_client = response["UserPoolClient"]
        eh.add_log("Created User Pool Client", response)
        eh.add_props({
            "name": user_pool_client['ClientName'],
            "id": user_pool_client["ClientId"],
            "secret": user_pool_client["ClientSecret"],
            "user_pool_id": user_pool_client["UserPoolId"]
        })

        eh.add_links({
            "User Pool Clients": gen_cognito_user_pool_client_link(region, user_pool_client["UserPoolId"])
        })

    except ClientError as e:
        handle_common_errors(e, eh, "Error Creating User Pool Client", 20, [
            "InvalidParameterException", "NotAuthorizedException",
            "LimitExceededException", "ScopeDoesNotExistException",
            "InvalidOAuthFlowException"
        ])

@ext(handler=eh, op="update_user_pool_client")
def update_user_pool_client(attributes, account_number, region):
    user_pool_client_id = eh.ops["update_user_pool_client"]["id"]
    try:
        update_attributes = {
            k:v for k,v in attributes.items() if 
            k not in ["GenerateSecret"]
        }
        update_attributes["ClientId"] = user_pool_client_id

        response = cognito.update_user_pool_client(**update_attributes)
        eh.add_log("Updated User Pool Client", response)

    except ClientError as e:
        handle_common_errors(e, eh, "Error Updating User Pool Client", 20, [
            "InvalidParameterException", "NotAuthorizedException",
            "LimitExceededException", "ScopeDoesNotExistException",
            "InvalidOAuthFlowException"
        ])

def gen_cognito_user_pool_client_link(region, user_pool_id):
    return f"https://{region}.console.aws.amazon.com/cognito/users?region={region}/pool/{user_pool_id}/clients"

@ext(handler=eh, op="delete_user_pool_client")
def delete_user_pool_client():
    op_info = eh.ops['delete_user_pool_client']
    user_pool_client_id = op_info['id']
    user_pool_id = op_info['user_pool_id']

    try:
        cognito.delete_user_pool_client(
            UserPoolId = user_pool_id,
            ClientId = user_pool_client_id
        )
        eh.add_log("User Pool Client Deleted", {"user_pool_client_id": user_pool_client_id})

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            eh.add_log("Old User Pool Client Doesn't Exist", {"user_pool_client_id": user_pool_client_id})
        else:
            handle_common_errors(e, eh, "Error Deleting User Pool Client", progress=20)
