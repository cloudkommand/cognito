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
        
        user_pool_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname, max_chars=100)
        
        password_policy = cdef.get("password_policy") or {
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireLowercase": True,
                "RequireUppercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "TemporaryPasswordValidityDays": 7
            }
        }

        lambda_config = remove_none_attributes({
            "PreSignUp": cdef.get("pre_sign_up_lambda_arn"),
            "CustomMessage": cdef.get("custom_message_lambda_arn"),
            "PostConfirmation": cdef.get("post_confirmation_lambda_arn"),
            "PreAuthentication": cdef.get("pre_authentication_lambda_arn"),
            "PostAuthentication": cdef.get("post_authentication_lambda_arn"),
            "DeferredAuthentication": cdef.get("deferred_authentication_lambda_arn"),
            "DefineAuthChallenge": cdef.get("define_auth_challenge_lambda_arn"),
            "CreateAuthChallenge": cdef.get("create_auth_challenge_lambda_arn"),
            "VerifyAuthChallengeResponse": cdef.get("verify_auth_challenge_response_lambda_arn"),
            "PreTokenGeneration": cdef.get("pre_token_generation_lambda_arn"),
            "UserMigration": cdef.get("user_migration_lambda_arn"),
            "CustomSMSSender": remove_none_attributes({
                "LambdaVersion": "V1_0" if cdef.get("custom_sms_sender_lambda_arn") else None,
                "Arn": cdef.get("custom_sms_sender_lambda_arn")
            }) or None,
            "CustomEmailSender": remove_none_attributes({
                "LambdaVersion": "V1_0" if cdef.get("custom_email_sender_lambda_arn") else None,
                "Arn": cdef.get("custom_email_sender_lambda_arn") or None
            }) or None,
            "KMSKeyID": cdef.get("kms_key_id"),
        })

        auto_verified_attributes = cdef.get("auto_verified_attributes") or ["email"]
        alias_attributes = cdef.get("alias_attributes") or ["preferred_username", "phone_number", "email"]
        username_attributes = cdef.get("username_attributes") or None

        sms_verification_message = cdef.get("sms_verification_message") or "Your verification code is {####}"
        email_verification_message = cdef.get("email_verification_message") or "Your verification code is {####}"
        email_verification_subject = cdef.get("email_verification_subject") or "Your Verification Code"
        verification_message_template = remove_none_attributes({
            "SmsMessage": sms_verification_message,
            "EmailMessage": email_verification_message,
            "EmailSubject": email_verification_subject,
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
        })
        sms_authentication_message = cdef.get("sms_authentication_message") or "Your authentication code is {####}. "
        mfa_configuration = cdef.get("mfa") or "OFF"
        user_attribute_update_settings = cdef.get("user_attribute_update_settings")

        remember_device = cdef.get("remember_device") or "ALWAYS"

        if remember_device == "ALWAYS":
            device_config = {
                "ChallengeRequiredOnNewDevice": False,
                "DeviceOnlyRememberedOnUserPrompt": False,
            }
        elif remember_device == "USER_OPT_IN":
            device_config = {
                "ChallengeRequiredOnNewDevice": False,
                "DeviceOnlyRememberedOnUserPrompt": True,
            }
        elif remember_device == "NEVER":
            device_config = None

        email_configuration = remove_none_attributes({
            "SourceArn": cdef.get("ses_email_address_arn"),
            "ReplyToEmailAddress": cdef.get("reply_to_email_address"),
            "EmailSendingAccount": "DEVELOPER" if cdef.get("ses_email_address_arn") else "COGNITO_DEFAULT",
        })

        sms_configuration = remove_none_attributes({
            "SnsCallerArn": cdef.get("sms_role_arn"),
            "ExternalId": cdef.get("sms_external_id"),
            "SnsRegion": cdef.get("sms_region")
        }) or None

        admin_create_user_config = {
            "AllowAdminCreateUserOnly": cdef.get("allow_admin_create_user_only") or False,
            "UnusedAccountValidityDays": cdef.get("unused_invite_validity_days") or 7,
            "InviteMessageTemplate": {
                "SMSMessage": cdef.get("invite_sms_message") or 'Your username is {username} and temporary password is {####}. ',
                "EmailMessage": cdef.get("invite_email_message") or 'Your username is {username} and temporary password is {####}. ',
                "EmailSubject": cdef.get("invite_email_subject") or 'Your temporary password',
            }
        }

        user_pool_add_ons = {
            "AdvancedSecurityMode": cdef.get("advanced_security_mode") or "OFF",
        }

        required_attributes = cdef.get("sign_up_required_attributes") or []

        schema = [
            {
                'Name': 'sub',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': False,
                'Required': True,
                'StringAttributeConstraints': {
                'MinLength': '1',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'name',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("name" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'given_name',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("given_name" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'family_name',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("family_name" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'middle_name',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("middle_name" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'nickname',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("nickname" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'preferred_username',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("preferred_username" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'profile',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("profile" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'picture',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("picture" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'website',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("website" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'email',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("email" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'email_verified',
                'AttributeDataType': 'Boolean',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
            },
            {
                'Name': 'gender',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("gender" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'birthdate',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("birthdate" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '10',
                'MaxLength': '10'
                }
            },
            {
                'Name': 'zoneinfo',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("zoneinfo" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'locale',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("locale" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'phone_number',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("phone_number" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            # {
            #     'Name': 'phone_number_verified',
            #     'AttributeDataType': 'Boolean',
            #     'DeveloperOnlyAttribute': False,
            #     'Mutable': True,
            #     'Required': False
            # },
            {
                'Name': 'address',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': bool("address" in required_attributes),
                'StringAttributeConstraints': {
                'MinLength': '0',
                'MaxLength': '2048'
                }
            },
            {
                'Name': 'updated_at',
                'AttributeDataType': 'Number',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0'
                }
            }
        ]

        if cdef.get("custom_attributes"):
            schema.extend(cdef["custom_attributes"])

        username_configuration = {
            "CaseSensitive": cdef.get("username_case_sensitive") or False,
        }

        account_recovery_setting = {
            "RecoveryMechanisms": [
                {
                    "Priority": 1,
                    "Name": "verified_email",
                },
                {
                    "Priority": 2,
                    "Name": "verified_phone_number"
                }
            ] if not cdef.get("prefer_phone_number_recovery") else [
                {
                    "Priority": 1,
                    "Name": "verified_phone_number",
                },
                {
                    "Priority": 2,
                    "Name": "verified_email"
                }
            ]  
        }

        tags = cdef.get("tags")

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
            "PoolName": user_pool_name,
            "Policies": password_policy,
            "LambdaConfig": lambda_config,
            "AutoVerifiedAttributes": auto_verified_attributes,
            "AliasAttributes": alias_attributes,
            "UsernameAttributes": username_attributes,
            "SmsVerificationMessage": sms_verification_message,
            "EmailVerificationMessage": email_verification_message,
            "EmailVerificationSubject": email_verification_subject,
            "VerificationMessageTemplate": verification_message_template,
            "SmsAuthenticationMessage": sms_authentication_message,
            "UserAttributeUpdateSettings": user_attribute_update_settings,
            "MfaConfiguration": mfa_configuration,
            "DeviceConfiguration": device_config,
            "EmailConfiguration": email_configuration,
            "SmsConfiguration": sms_configuration,
            "UserPoolTags": tags,
            "AdminCreateUserConfig": admin_create_user_config,
            "Schema": schema,
            "UserPoolAddOns": user_pool_add_ons,
            "UsernameConfiguration": username_configuration,
            "AccountRecoverySetting": account_recovery_setting,
        })

        # attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        print(attributes)

        get_user_pool(attributes, cdef)
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
def get_user_pool(attributes, cdef,):
    user_pool_id = eh.state["user_pool_id"]
    try:
        response = cognito.describe_user_pool(
            UserPoolId=user_pool_id
        )

        user_pool = response["UserPool"]
        eh.add_log("Got User Pool", response)
        print(f"current_attributes = {user_pool}")
        for k,v in attributes.items():
            if k not in ["Schema", "PoolName"] and (str(user_pool.get(k)).lower() != str(v).lower()):
                eh.add_op("update_user_pool")
                print(k)
                print(v)
                print(type(k))
                print(type(v))
                break

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
            "User Pool": gen_cognito_user_pool_link(region, response["Id"])
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
        user_pool = response["UserPool"]
        eh.add_log("Created User Pool", response)
        eh.add_props({
            "name": user_pool['Name'],
            "id": user_pool["Id"],
            "arn": user_pool["Arn"]
        })

        eh.add_links({
            "User Pool": gen_cognito_user_pool_link(region, response["Id"])
        })

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
