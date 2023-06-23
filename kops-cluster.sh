#!/bin/bash -xe

sleep 200
aws s3api put-bucket-versioning --bucket $bucket  --versioning-configuration Status=Enabled
export KOPS_STATE_STORE=s3://$bucket

kops create cluster --name $clustername-cluster.k8s.local  --zones $zone1  --networking amazonvpc --topology private  --dns private --yes
sleep 800
kubectl apply -f Deployment
