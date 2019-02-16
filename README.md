# Twilio Pager

internal server used to bridge grafana notifications to twilio flows

This server will respond to grafana webhooks and trigger a twillio flow for every recipient in the config

## Configuration

Configs look something like this:
```
[Twilio]
sid=YourProjectSID
auth_token=YourProjectAuthToken

[YourFlowName]
sid=TwilioFlowSID
From=YourTwilioNumber

[YourFlowName.recipients]
Someone=number
Someoneelse=number
```

## Installation

```
mkdir -p /opt/twilio-pager
cp server.py /opt/twilio-pager

mkdir /etc/twilio-pager
vim /etc/twilio-pager/twilio-pager.ini
# See configuration section above

mkdir /var/log/twilio-pager

sudo cp twilio-pager.service /etc/systemd/system/multi-user.target.wants/
sudo systemctl enable twilio-pager.service
sudo systemctl start twilio-pager.service
```

