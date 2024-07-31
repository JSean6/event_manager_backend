import requests
from django.conf import settings

def send_ticket_email(to_email, subject, content):
    return requests.post(
        f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
        auth=("api", settings.MAILGUN_API_KEY),
        data={"from": f"Excited User <mailgun@{settings.MAILGUN_DOMAIN}>",
              "to": [to_email],
              "subject": subject,
              "html": content})
