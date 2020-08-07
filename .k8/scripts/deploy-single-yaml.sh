#!/bin/bash

set -x

if [[ -z $1 ]]; then
  echo "Please provide IMAGENAME"
  exit 1
fi

if [[ -z $2 ]]; then
  echo "Please provide IMAGETAG"
  exit 1
fi

if [[ -z $3 ]]; then
  echo "Please provide NAMESPACE"
  exit 1
fi

if [[ -z $4 ]]; then
  echo "Please provide number of replicas"
  exit 1
fi

if [[ -z $5 ]]; then
  echo "Please provide deployment type: prod|stage"
  exit 1
fi

if [[ -z $6 ]]; then
  echo "Please provide k8s context"
  exit 1
fi

if [[ -z $7 ]]; then
  echo "Pleae provide domain suffix"
  exit 1
fi

if [[ -z $8 ]]; then
  echo "Please provide k8s app version"
  exit 1
fi


IMAGENAME=$1
IMAGETAG=$2
NAMESPACE=$3
YAML_FILE=$4
DEPL_TYPE=$5
K8S_CONTEXT=$6
DOMAIN_SUFFIX=$7
K8S_API_VERSION=$8

echo $IMAGENAME
echo $IMAGETAG
echo $NAMESPACE
echo $YAML_FILE
echo $DEPL_TYPE
echo $K8S_CONTEXT
echo $DOMAIN_SUFFIX
echo $K8S_API_VERSION

# create namespace if not exists
if ! kubectl --context=$K8S_CONTEXT get ns | grep -q $NAMESPACE; then
  echo "$NAMESPACE created"
  kubectl --context=$K8S_CONTEXT create namespace $NAMESPACE
fi

if [[ -f .k8/${YAML_FILE} ]]; then
   sed -i -e "s|REPLACE_NAMESPACE|${NAMESPACE}|g" \
          -e "s|REPLACE_IMAGE|${IMAGENAME}|g" \
          -e "s|REPLACE_DOMAIN_SUFFIX|${DOMAIN_SUFFIX}|g" \
          -e "s|REPLACE_API_VERSION|${K8S_API_VERSION}|g" \
          -e "s|REPLACE_IMAGETAG|${IMAGETAG}|g" ".k8/${YAML_FILE}" || exit 1
fi

#deploy
kubectl --context=$K8S_CONTEXT apply -f .k8/${YAML_FILE} --wait=true || exit 1