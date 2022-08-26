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

        generate_secret = cdef.get("generate_secret", True)

        access_token_expiration_minutes = cdef.get("access_token_expiration_minutes", 60)
        refresh_token_expiration_minutes = cdef.get("refresh_token_expiration_minutes", 43200)
        refresh_token_unit = "minutes"
        id_token_expiration_minutes = cdef.get("id_token_expiration_minutes", 60)
        if refresh_token_expiration_minutes % (60*24) == 0:
            refresh_token_expiration_minutes = refresh_token_expiration_minutes /(60*24)
            refresh_token_unit = "days"

        read_attributes = cdef.get("read_attributes") or None
        write_attributes = cdef.get("write_attributes") or None

        auth_flows = cdef.get("auth_flows") or ["ALLOW_CUSTOM_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
        supported_identity_providers = cdef.get("supported_identity_providers") or ["COGNITO"]

        callback_urls = cdef.get("callback_urls") or None
        logout_urls = cdef.get("logout_urls") or None
        default_redirect_uri = cdef.get("default_redirect_uri")

        oauth_flows = cdef.get("oauth_flows") or ["code", "implicit", "client_credentials"]
        oauth_scopes = cdef.get("oauth_scopes")

        prevent_user_existence_errors = cdef.get("prevent_user_existence_errors") or "ENABLED"
        token_revocation = cdef.get("token_revocation") or False
        enable_propagate_additional_user_context_data = cdef.get("enable_propagate_additional_user_context_data") or False

        
        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass

        elif event.get("op") == "upsert":
            if prev_state.get("props", {}).get("id"):
                eh.add_op("get_user_pool")
                eh.add_state({
                    "user_pool_id": prev_state.get("props", {}).get("id")
                })
            else:
                eh.add_op("create_user_pool")

            # if domain:
            #     eh.add_op("get_domain")
            # elif prev_state.get("props", {}).get("domain"):
            #     eh.add_op("delete_domain", {"domain": domain})

        elif event.get("op") == "delete":
            eh.add_op("delete_user_pool", {"id":prev_state.get("props", {}).get("id"), "only_delete": True})
        
        attributes = remove_none_attributes({
            "UserPoolId": user_pool_id,
            "ClientName": client_name,
            "GenerateSecret": generate_secret,
            "RefreshTokenValidity": refresh_token_expiration_minutes,
            "AccessTokenValidity": access_token_expiration_minutes,
            "IdTokenValidity": id_token_expiration_minutes,
            "TokenValidityUnits": {
                "AccessToken": "MINUTES",
                "RefreshToken": refresh_token_unit,
                "IdToken": "MINUTES"
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
            "EnablePropagateAdditionalUserContextData": enable_propagate_additional_user_context_data
        })

        # attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        print(attributes)

        get_user_pool(attributes, cdef, region)
        create_user_pool(attributes, account_number, region)
        update_user_pool(attributes, account_number, region)
        delete_user_pool()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_user_pool")
def get_user_pool(attributes, cdef, region):
    user_pool_id = eh.state["user_pool_id"]
    try:
        response = cognito.describe_user_pool(
            UserPoolId=user_pool_id
        )

        user_pool = response["UserPool"]
        eh.add_log("Got User Pool", response)
        print(f"current_attributes = {user_pool}")

        #Loop through the attributes and compare them to the current attributes
        #If they are different, then update the user pool
        for k,v in attributes.items():

            #If we are working with the password policy, remove temp_valid_days from comparison
            if k == "Policies":
                current_pp = user_pool["Policies"].get("PasswordPolicy", {})
                desired_pp = v["PasswordPolicy"]
                _ = current_pp.pop("TemporaryPasswordValidityDays", None)
                print(f"current_pp = {current_pp}")
                print(f"desired_pp = {desired_pp}")
                if current_pp != desired_pp:
                    eh.add_op("update_user_pool", {"id": user_pool_id, "attributes": attributes})
                    break
                
            elif k not in ["Schema", "PoolName"] and (str(user_pool.get(k)).lower() != str(v).lower()):
                eh.add_op("update_user_pool")
                print(k)
                print(v)
                print(type(k))
                print(type(v))
                break

        eh.add_props({
            "name": user_pool['Name'],
            "id": user_pool["Id"],
            "arn": user_pool["Arn"]
        })

        eh.add_links({
            "User Pool": gen_cognito_user_pool_link(region, user_pool["Id"])
        })

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            eh.add_op("create_user_pool")
        else:
            handle_common_errors(e, eh, "Get User Pool Failure", 0)


@ext(handler=eh, op="create_user_pool")
def create_user_pool(attributes, account_number, region):
    try:
        response = cognito.create_user_pool(**attributes)
        user_pool = response["UserPool"]
        eh.add_log("Created User Pool", response)
        eh.add_props({
            "name": user_pool['Name'],
            "id": user_pool["Id"],
            "arn": user_pool["Arn"]
        })

        eh.add_links({
            "User Pool": gen_cognito_user_pool_link(region, user_pool["Id"])
        })

    except ClientError as e:
        handle_common_errors(e, eh, "Error Creating User Pool", 20, [
            "InvalidParameterException", "NotAuthorizedException",
            "LimitExceededException", "InvalidSmsRoleAccessPolicyException",
            "InvalidSmsRoleTrustRelationshipException", "InvalidEmailRoleAccessPolicyException"
        ])

@ext(handler=eh, op="update_user_pool")
def update_user_pool(attributes, account_number, region):
    user_pool_id = eh.state["user_pool_id"]
    try:
        update_attributes = {
            k:v for k,v in attributes.items() if 
            k not in ["PoolName", "AliasAttributes", "UsernameAttributes", 
            "UsernameConfiguration", "Schema"]
        }
        update_attributes["UserPoolId"] = user_pool_id

        response = cognito.update_user_pool(**update_attributes)
        # print(f"response = {response}")
        # user_pool = response["UserPool"]
        eh.add_log("Updated User Pool", response)
        # eh.add_props({
        #     "name": user_pool['Name'],
        #     "id": user_pool["Id"],
        #     "arn": user_pool["Arn"]
        # })

        # eh.add_links({
        #     "User Pool": gen_cognito_user_pool_link(region, response["Id"])
        # })

    except ClientError as e:
        handle_common_errors(e, eh, "Error Creating User Pool", 20, [
            "InvalidParameterException", "NotAuthorizedException",
            "LimitExceededException", "InvalidSmsRoleAccessPolicyException",
            "InvalidSmsRoleTrustRelationshipException", "InvalidEmailRoleAccessPolicyException"
        ])

def gen_cognito_user_pool_link(region, user_pool_id):
    return f"https://{region}.console.aws.amazon.com/cognito/users?region={region}/home?region={region}#/pool/{user_pool_id}/details"

@ext(handler=eh, op="delete_user_pool")
def delete_user_pool():
    op_info = eh.ops['delete_user_pool']
    user_pool_id = op_info['id']
    only_delete = op_info.get("only_delete")

    try:
        cognito.delete_user_pool(
            UserPoolId = user_pool_id
        )
        eh.add_log("User Pool Deleted", {"user_pool_id": user_pool_id})

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            eh.add_log("Old User Pool Doesn't Exist", {"user_pool_id": user_pool_id})
        else:
            handle_common_errors(e, eh, "Error Deleting User Pool", progress=(95 if only_delete else 20))
