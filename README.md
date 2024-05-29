Webhook validation poc
==================
This is a simple proof of concept to validate a webhook from a third party service.
For try this example you need kind cluster and kubectl installed.
Then simply run sh `create_csr.sh` and try to create a pod with the webhook configuration (`kubectl apply -f pod.yaml`).
For this example every pod with `activeDeadLineSeconds` bigger than 120 seconds will be rejected.
create.sh scrips will perform the following steps:
1. generate a private key and a csr
2. create CertificateSigningRequest to k8s
3. approve the csr
4. build image with the webhook server
5. deploy the webhook server (as a service linked to the pod with the webhook server image)
6. create a validating webhook configuration