# voucher

Service to serve aws metadata API as a sidecar

Build:

```
docker build -t voucher .
```

Run:

```
aws-vault exec <account> -- sh -c 'docker run --privileged --rm -ti -e AWS_REGION -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN voucher /bin/bash -c "capture-metadata-traffic.sh && (voucher -session-tokens=false &) && unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN && /bin/bash"'
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/voucher
aws sts get-caller-identity
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/voucher
```

Testing inside a pod:

```
AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url https://sts.us-east-1.amazonaws.com sts get-caller-identity
```
