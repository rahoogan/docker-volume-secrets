# Docker Secrets Volume Plugin
![workflow status](https://github.com/rahoogan/docker-volume-secrets/actions/workflows/go.yml/badge.svg?main)

An extensible docker volume plugin to manage remote secrets. Enables secrets to be mounted as volumes into containers. Currently works with AWS Secrets Manager

Currently works with [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html).

## 1. Installation

Install from dockerhub using the managed docker plugin system:

```bash
docker plugin install --alias dsv rahoogan/dsv
```

## 2. Configure

Configure the plugin with your AWS credentials:

```bash
docker plugin disable rahoogan/dsv

docker plugin set rahoogan/dsv AWS_ACCESS_KEY_ID="YOUR AWS KEY"
docker plugin set rahoogan/dsv AWS_SECRET_ACCESS_KEY="YOUR AWS SECRET"
docker plugin set rahoogan/dsv AWS_REGION="us-east-2"
# Optional - if using localstack for example
docker plugin set rahoogan/dsv AWS_ENDPOINT_URL="http://172.17.0.2:4566"
# Optional - to enable debug logging
docker plugin set rahoogan/dsv DEBUG=1

docker plugin enable rahoogan/dsv
```

## 3. Run it!

```bash
# Create a secret in secrets manager
$ aws secrets-manager create-secret --name mysecret --secret-string "dontlookatme!"

# Mount the secret as a volume in a container
$ docker run --rm --volume-driver dsv -v mysecret:/run/secrets/hello ubuntu cat /run/secrets/hello
dontlookatme!

# Alternatively, you could also use the --mount option
$ docker run --rm --mount type=volume,volume-driver=dsv,src=mysecret,target=/run/secrets/mysecret ubuntu cat /run/secrets/mysecret
dontlookatme!
```


## 4. Security

**DON'T USE THIS ON A SHARED SYSTEM!**

The secrets managed by the plugin are stored on a docker managed container. So anyone who can run `docker` commands can see your secrets.

Also, it’s trivial to just inspect the plugin to get the stored AWS credentials:

```
docker plugin inspect dsv -f "{{ .Settings.Env }}"
[DEBUG=1 AWS_ACCESS_KEY_ID=<YOUR_AWS_KEY> AWS_SECRET_ACCESS_KEY=<YOUR_AWS_SECRET> AWS_REGION=us-east-2 AWS_ENDPOINT_URL=http://172.17.0.2:4566]
```

So yeah, just make sure you use this on a development or local machine where only you have access, or where docker access is managed via an authorization plugin.

