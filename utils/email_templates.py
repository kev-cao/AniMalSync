import boto3
import os
from botocore.exceptions import ClientError

ses = boto3.client('ses', region_name=os.environ['AWS_REGION_NAME'])

# Email Verification Template
verif_template_name = 'AniMalSync_Email_Verification'
verif_html = """
<h2>AniMalSync</h2>
<p>
This email address was registered on AniMalSync.
If this was you, click <a href={{url}}>this link to verify your email address.</a>
</p>
<br />
<p>If you did not register for an account, you may disregard this email.</p>
"""

verif_text = """
This email address was registered on AniMalSync.
If this was you, click this link to verify your email address: {{url}}

If you did not register for an account, you may disregard this email.
"""

try:
    resp = ses.get_template(
        TemplateName=verif_template_name
    )
except ClientError as e:
    if e.response['Error']['Code'] == 'TemplateDoesNotExist':
        ses.create_template(
            Template={
                'TemplateName': verif_template_name,
                'SubjectPart': 'AniMalSync Email Verification',
                'TextPart': verif_text,
                'HtmlPart': verif_html
            }
        )
    else:
        raise e
else:
    ses.update_template(
        Template={
            'TemplateName': verif_template_name,
            'SubjectPart': 'AniMalSync Email Verification',
            'TextPart': verif_text,
            'HtmlPart': verif_html
        }
    )


# MAL Authorization Template Template
auth_template_name = 'AniMalSync_MAL_Auth'
auth_html = """
<h2>AniMalSync MAL Authorization</h2>
<p>AniMalSync needs you to authorize the app to access your MyAnimeList account. Please click <a href="{{url}}">this link to authorize the app.</a></p>
"""

auth_text = """
AniMalSync needs you to authorize the app to access your MyAnimeList account.
Please click this link to authorize the app: {{url}}
"""

try:
    resp = ses.get_template(
        TemplateName=auth_template_name
    )
except ClientError as e:
    if e.response['Error']['Code'] == 'TemplateDoesNotExist':
        ses.create_template(
            Template={
                'TemplateName': auth_template_name,
                'SubjectPart': 'AniMalSync MAL Authorization',
                'TextPart': auth_text,
                'HtmlPart': auth_html
            }
        )
    else:
        raise e
else:
    ses.update_template(
        Template={
            'TemplateName': auth_template_name,
            'SubjectPart': 'AniMalSync MAL Authorization',
            'TextPart': auth_text,
            'HtmlPart': auth_html
        }
    )


# Reset Password Template
reset_password_template_name = 'AniMalSync_MAL_Reset_Password'
reset_password_html = """
<h2>AniMalSync Password Reset</h2>
<p>We received a request to reset the password for your account. To reset your password, click <a href="{{url}}">this link.</a></p>
<br />
<p>If you did not request this reset, you may disregard this email.</p>
"""

reset_password_text = """
AniMalSync received a request to reset the password for your account. To reset your password, please click this link: {{url}}.


If you did not request this reset, you may disregard this email.
"""

try:
    resp = ses.get_template(
        TemplateName=reset_password_template_name
    )
except ClientError as e:
    if e.response['Error']['Code'] == 'TemplateDoesNotExist':
        ses.create_template(
            Template={
                'TemplateName': reset_password_template_name,
                'SubjectPart': 'AniMalSync Password Reset',
                'TextPart': reset_password_text,
                'HtmlPart': reset_password_html
            }
        )
    else:
        raise e
else:
    ses.update_template(
        Template={
            'TemplateName': reset_password_template_name,
            'SubjectPart': 'AniMalSync Password Reset',
            'TextPart': reset_password_text,
            'HtmlPart': reset_password_html
        }
    )
