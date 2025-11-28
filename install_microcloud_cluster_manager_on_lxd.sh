#!/bin/bash

EXPECT_EXIST=false                  # determines if we assume the elements exist or
                                    # not. when false we expect an empty environement
                                    # and create the project, the profile ... etc.
                                    # when true, we assume the env exists and we delete it
PROJECT=k8s-project                 # LXD project in which to create everything
NETWORK=br0                         # LXD network used for the project and the k8s VMs
VM_STORAGE_POOL=default             # storage pool for VM creation
PROFILE=k8s-profile                 # profile for k8s VMs

CPU=8                               # k8s VM sizing (set in profile)
MEMORY=16GiB
MEMBERS=( k1 k2 k3 )                # k8s VMs to create

MICROCEPH=false                     # configure and use microceph for storage (or not)
OSD_SIZE=100GiB
CEPH_CSI_REPO=raw.githubusercontent.com/ceph/ceph-csi/master/deploy/rbd/kubernetes

CSI_STORAGE_POOL=default            # storage pool for LXD's CSI (when not useing ceph's)
AUTHGROUP=k8s-group                 # identity and permissions for LXD's CSI
DEVLXDID=csi
CSINAMESPACE=lxd-csi                # k8s namespace for LXD's CSI, matches what is in the helm chart

                                    # must be reserved on $NETWORK above
METALLB_IP_RANGE=192.168.67.50-192.168.67.59

JUJUCTRL=k8s-on-sm                  # juju controller on k8s

if [ -z ${USERNAME} ]; then         # regular user created in k8s VMs
    USERNAME=egelinas
fi

if [ -z ${LP_USER} ]; then          # regular user's launchpad account to get SSH key
    LP_USER=egelinas
fi

FIRST_NAME=Eric                     # keycloak user
LAST_NAME=Gelinas
EMAIL=eric.gelinas@canonical.com
PASSWORD=ubuntu

# TODO
#
# single node ceph is not possible
# requires latest lxd, check for that
# VM Ready will only work on first boot.
# jq not available on jammy
# lxc_exec vs sudo_k8s and jq commands

# ------------------------------------------------------------------------------

# functions use the same pattern and are built to be idempotent.
# we first validate the assumption (if items are expected to be present or not)
# we create them if they don't exist and delete them if they do

# we product a json list the items (-f json), make sure they show up in an array and
# test if any of the items match what we are targeting

project() {
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == ${EXPECT_EXIST} ]]; then

        # here our assumption tested true, we create the project if it does not exist
        # and delete it if it does.

        if [[ ${EXPECT_EXIST} == "false" ]]; then
            lxc project create ${PROJECT} -n ${NETWORK} -s ${VM_STORAGE_POOL}
        else
            lxc project delete ${PROJECT} -f
        fi

        # there is nothing to do if our assumption is wrong. expect == false means we need to create the
        # project but it is already there. expect == true means we need to delete the project but it
        # does not exist so we are ok
    fi
}

vm_profile() {

    # same logic as the project function except we only do something about the profile if the project exists
    #
    # the profile uses the LXD api to set the state of VMs to "Ready" using curl when snap commands
    # have been executed, this flag is used to validate that products are ready to be initialized
    # it also sets the right flags for VMs to access /dev/lxd for the CSI
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        if [[ "$(lxc profile list --project ${PROJECT} -f json | jq "[.[].name] | any(. == \"${PROFILE}\")")" == ${EXPECT_EXIST} ]]; then    
            if [[ ${EXPECT_EXIST} == "false" ]]; then
                cat <<EOF > profile.yaml
config:
  cloud-init.network-config: |
    network:
      version: 2
      ethernets:
        enp5s0:
          dhcp4: true
  cloud-init.user-data: |
    #cloud-config
    users:
      - name: ${USERNAME}
        ssh_import_id:
          - lp: ${LP_USER}
        shell: /usr/bin/bash
        sudo: ALL=(root) NOPASSWD:ALL
    runcmd:
      - [ sudo, snap, install, microceph, --channel=squid/stable, --cohort="+" ]
      - [ sudo, snap, install, k8s, --classic, --cohort="+" ]
      - [ curl, --unix-socket, /dev/lxd/sock, lxd/1.0, --request, PATCH, --data, '{"state":"Ready"}' ]
  limits.cpu: ${CPU}
  limits.memory: ${MEMORY}
  security.devlxd.images: true
  security.devlxd.management.volumes: true
  migration.stateful: false
description: CanonicalK8s Node
devices:
  eth0:
    name: eth0
    nictype: bridged
    parent: ${NETWORK}
    type: nic
  root:
    path: /
    pool: default
    size: 100GB
    type: disk
name: ${PROFILE}
EOF
                # < profile.yaml bugs with /dev/stdin not being readable
                cat profile.yaml | lxc profile create ${PROFILE} --project ${PROJECT}
                rm profile.yaml
            fi
        fi
    fi
}

group_and_permissions() {

    if [[ "$(lxc auth group list -f json | jq "[.[].name] | any(. == \"${AUTHGROUP}\")")" == ${EXPECT_EXIST} ]]; then
        if [[ ${EXPECT_EXIST} == "false" ]]; then
            lxc auth group create ${AUTHGROUP}
        
            lxc auth group permission add ${AUTHGROUP} project ${PROJECT} can_view
            lxc auth group permission add ${AUTHGROUP} project ${PROJECT} storage_volume_manager
            lxc auth group permission add ${AUTHGROUP} project ${PROJECT} can_edit_instances
        else
            # project will have been deleted
            lxc auth group delete ${AUTHGROUP}
        fi  
    fi
}

identity() {

    if [[ "$(lxc auth identity list -f json | jq "[.[].name] | any(. == \"${DEVLXDID}\")")" == ${EXPECT_EXIST} ]]; then    
        if [[ ${EXPECT_EXIST} == "false" ]]; then
            lxc auth identity create devlxd/${DEVLXDID}
            printf "\n"
            lxc auth identity group add devlxd/${DEVLXDID} ${AUTHGROUP}
            DEVLXD_TOKEN=$(lxc auth identity token issue devlxd/${DEVLXDID} --quiet)
        else
            # group will have been deleted
            lxc auth identity delete devlxd/${DEVLXDID}
        fi
    else
        
        # here we need to act on our failed assumption, the identity exists and it's ok
        # but we need to get a token for it
        
        if [[ ${EXPECT_EXIST} == "false" ]]; then
            DEVLXD_TOKEN=$(lxc auth identity token issue devlxd/${DEVLXDID} --quiet)
        fi
    fi
}

vms() {

    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        for i in ${MEMBERS[@]}; do
            if [[ "$(lxc list --project ${PROJECT} -f json | jq "[.[].name] | any(. == \"${i}\")")" == "false" ]]; then    
                lxc init ubuntu:noble ${i} --project ${PROJECT} --profile ${PROFILE} --vm
                if [[ "${MICROCEPH}" == "true" ]]; then
                    lxc storage volume create ${VM_STORAGE_POOL} --project ${PROJECT} ${i}ceph size=${OSD_SIZE} --type=block
                    lxc config device add ${i} disk${i} disk --project ${PROJECT} pool=${VM_STORAGE_POOL} source=${i}ceph
                fi
                lxc start ${i} --project ${PROJECT}
            fi
        done

        # waiting for all machines to be ready
        
        while [[ "$(lxc list --project ${PROJECT} -f json | jq "[.[].status] | all(. == \"Ready\")")" == "false" ]]; do
            echo "Waiting for VMs to be ready"
            sleep 10
        done
    fi
}

# syntactic sugar functions
# lxc_exec* are not used when the command needs to be executed on another node than the main one

lxc_exec() {
    lxc exec ${MEMBERS[0]} --project ${PROJECT} -- ${1}
}

lxc_exec_user() {
    lxc exec ${MEMBERS[0]} --project ${PROJECT} -- su - ${USERNAME} -c "${1}"
}

sudo_microceph() {
    lxc_exec_user "sudo microceph ${1}"
}

sudo_k8s() {
    lxc_exec_user "sudo k8s ${1}"
}

# cluster creation functions will consider actions only when the project exists
# if it was previously deleted then nothing happens, if present we first test for the existance
# of the cluster and create it if it isn't there.
#
# the first node is initialized and other nodes are joined if needed

k8s_cluster() {

    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then

        sudo_k8s "status"

        if [ $? -ne 0 ]; then

            sudo_k8s "bootstrap"

            # add all other nodes to the main one
            for (( i=1; i<${#MEMBERS[@]}; i++ )); do
                JOIN_TOKEN=$(sudo_k8s "get-join-token ${MEMBERS[$i]}")
                lxc exec ${MEMBERS[$i]} --project ${PROJECT} -- su - ${USERNAME} -c "sudo k8s join-cluster ${JOIN_TOKEN}"
            done

            sudo_k8s "status --wait-ready"

            # for helm + juju
            
            lxc_exec_user "mkdir -p ~/.kube"
            lxc_exec_user "chmod 0700 ~/.kube"
            lxc_exec_user "sudo k8s config > ~/.kube/config"
        fi
    fi
}

microceph_cluster() {

    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        
        sudo_microceph "cluster list"

        if [ $? -ne 0 ]; then

            sudo_microceph "cluster bootstrap"

            # add all other nodes to the main one
            for (( i=1; i<${#MEMBERS[@]}; i++ )); do
                JOIN_TOKEN=$(sudo_microceph "cluster add ${MEMBERS[$i]}")
                lxc exec ${MEMBERS[$i]} --project ${PROJECT} -- su - ${USERNAME} -c "sudo microceph cluster join ${JOIN_TOKEN}"
            done

            # add OSDs
            for i in ${MEMBERS[@]}; do
                lxc exec ${i} --project ${PROJECT} -- su - ${USERNAME} -c "sudo microceph disk add /dev/sdb --wipe"
            done

            lxc_exec "ceph osd pool create kubernetes 128"
            lxc_exec "rbd pool init kubernetes"
        fi
    fi
}

ceph_csi() {
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        if [[ "$(sudo_k8s "kubectl get sc -o json | jq '[.items.[].metadata.name] | any(. == \"csi-rbd-sc\")'")" == "false" ]]; then            
            # 1)
            
            FSDI=$(lxc_exec "ceph fsid")
            MONS=$(lxc_exec "ceph mon dump -f json" | jq '[.mons.[].public_addr]' | tr -d '\n')

            cat <<EOF > csi-config-map.yaml
---
apiVersion: v1
kind: ConfigMap
data:
  config.json: |-
    [
      {
        "clusterID": "${FSDI}",
        "monitors": ${MONS}
      }
    ]
metadata:
  name: ceph-csi-config
EOF

            lxc file push csi-config-map.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/csi-config-map.yaml
            sudo_k8s "kubectl apply -f csi-config-map.yaml"
            rm csi-config-map.yaml

            # 2)

            cat <<EOF > csi-kms-config-map.yaml
---
apiVersion: v1
kind: ConfigMap
data:
  config.json: |-
    {}
metadata:
  name: ceph-csi-encryption-kms-config
EOF

            lxc file push csi-kms-config-map.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/csi-kms-config-map.yaml
            sudo_k8s "kubectl apply -f csi-kms-config-map.yaml"
            rm csi-kms-config-map.yaml

            # 3)

            cat <<EOF > ceph-config-map.yaml
---
apiVersion: v1
kind: ConfigMap
data:
  ceph.conf: |
    [global]
    auth_cluster_required = cephx
    auth_service_required = cephx
    auth_client_required = cephx
  # keyring is a required key and its value should be empty
  keyring: |
metadata:
  name: ceph-config
EOF

            lxc file push ceph-config-map.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/ceph-config-map.yaml
            sudo_k8s "kubectl apply -f ceph-config-map.yaml"
            rm ceph-config-map.yaml

            # 4) (tried using lxc_exec without sucess - quoting issue)
            SECRET_KEY=$(lxc exec ${MEMBERS[0]} --project ${PROJECT} -- ceph auth get-or-create client.kubernetes mon 'profile rbd' osd 'profile rbd pool=kubernetes' mgr 'profile rbd pool=kubernetes' -f json | jq '.[].key')
            
            cat <<EOF > csi-rbd-secret.yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: csi-rbd-secret
  namespace: default
stringData:
  userID: kubernetes
  userKey: ${SECRET_KEY}
EOF

            lxc file push csi-rbd-secret.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/csi-rbd-secret.yaml
            sudo_k8s "kubectl apply -f csi-rbd-secret.yaml"
            rm csi-rbd-secret.yaml

            # deploy csi

            sudo_k8s "kubectl apply -f https://${CEPH_CSI_REPO}/csi-provisioner-rbac.yaml"
            sudo_k8s "kubectl apply -f https://${CEPH_CSI_REPO}/csi-nodeplugin-rbac.yaml"
            sudo_k8s "kubectl apply -f https://${CEPH_CSI_REPO}/csi-rbdplugin-provisioner.yaml"
            sudo_k8s "kubectl apply -f https://${CEPH_CSI_REPO}/csi-rbdplugin.yaml"

            # create storage class (reuse cluster id)
            # set CSI_STORAGE_POOL to rbd when not using the LXD CSI (for juju)
            
            CSI_STORAGE_POOL=rbd
            
            cat <<EOF > csi-rbd-sc.yaml
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
   name: csi-${CSI_STORAGE_POOL}-sc
   annotations:
      storageclass.kubernetes.io/is-default-class: "true"
provisioner: rbd.csi.ceph.com
parameters:
   clusterID: ${FSDI}
   pool: kubernetes
   imageFeatures: layering
   csi.storage.k8s.io/provisioner-secret-name: csi-rbd-secret
   csi.storage.k8s.io/provisioner-secret-namespace: default
   csi.storage.k8s.io/controller-expand-secret-name: csi-rbd-secret
   csi.storage.k8s.io/controller-expand-secret-namespace: default
   csi.storage.k8s.io/node-stage-secret-name: csi-rbd-secret
   csi.storage.k8s.io/node-stage-secret-namespace: default
reclaimPolicy: Delete
allowVolumeExpansion: true
mountOptions:
   - discard
EOF

            lxc file push csi-rbd-sc.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/csi-rbd-sc.yaml
            sudo_k8s "kubectl apply -f csi-rbd-sc.yaml"
            rm csi-rbd-sc.yaml

            sudo_k8s "disable local-storage"
        fi
    fi
}

lxd_csi() {
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        if [[ "$(sudo_k8s "kubectl get sc -o json | jq '[.items.[].metadata.name] | any(. == \"csi-${CSI_STORAGE_POOL}-sc\")'")" == "false" ]]; then            
        
            sudo_k8s "kubectl create namespace ${CSINAMESPACE} --save-config"
            sudo_k8s "kubectl create secret generic lxd-csi-secret --namespace ${CSINAMESPACE} --from-literal=token=${DEVLXD_TOKEN}"
            lxc_exec_user "sudo snap install helm --classic"
            lxc_exec_user "helm install lxd-csi-driver oci://ghcr.io/canonical/charts/lxd-csi-driver --version v0-latest-edge --set snapshotter.enabled=true --namespace ${CSINAMESPACE}"
            
            cat <<EOF > csi-sc.yaml
---
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: csi-${CSI_STORAGE_POOL}-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: lxd.csi.canonical.com
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
parameters:
  storagePool: "${CSI_STORAGE_POOL}"
EOF

            lxc file push csi-sc.yaml --project ${PROJECT} ${MEMBERS[0]}/home/${USERNAME}/csi-sc.yaml
            sudo_k8s "kubectl apply -f csi-sc.yaml"
            rm csi-sc.yaml

            sudo_k8s "disable local-storage"
        fi
    fi
}

juju() {

    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then

        lxc_exec_user "sudo snap install juju"
        lxc_exec_user "sudo systemctl restart user@1000.service" # bug somewhere

        lxc_exec_user "juju list-models"

        if [ $? -ne 0 ]; then
            # set proper default to avoid using csi-rawfile-default
            lxc_exec_user "juju add-k8s ${JUJUCTRL} --cloud k8s --storage csi-${CSI_STORAGE_POOL}-sc"
            lxc_exec_user "juju bootstrap ${JUJUCTRL}"
        fi
    fi
}

cluster_manager_dependencies() {
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        if [[ "$(lxc_exec_user "juju list-models --format json | jq '[.models[].name] | any(. == \"admin/cluster-manager\")'")" == "false" ]]; then
            lxc_exec_user "juju add-model cluster-manager"

            lxc_exec_user "juju deploy metallb --config iprange='${METALLB_IP_RANGE}' --trust"
            lxc_exec_user "juju deploy postgresql-k8s --channel 14/stable --trust"
            lxc_exec_user "juju deploy self-signed-certificates --trust"
            lxc_exec_user "juju deploy traefik-k8s --trust"
        fi
    fi
}

keycloak() {

    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then

        sudo_k8s "kubectl apply -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/refs/heads/main/kubernetes/keycloak.yaml"
        # expose the UI via metal-lb
        sudo_k8s "kubectl patch service keycloak --type merge -p '{\"spec\":{\"type\":\"LoadBalancer\"}}'"
        
        while [[ "$(sudo_k8s "kubectl get services -o json | jq '[.items[].metadata.name] | any(. == \"keycloak\")'")" == "false" ]]; do
            echo "Waiting for keyclock service to be ready"
            sleep 10
        done

        while [[ "$(sudo_k8s "kubectl get services -o json | jq '.items[] | select(.metadata.name == \"keycloak\") | .status.loadBalancer.ingress[0].ip'")" == "null" ]]; do
            echo "Waiting for LoadBalancer IP"
            sleep 10
        done
        
        # use jq -r to remove quotes from IPs and ACCESS_TOKEN
        
        KEYCLOAK_IP=$(sudo_k8s "kubectl get services -o json | jq -r '.items[] | select(.metadata.name == \"keycloak\") | .status.loadBalancer.ingress[0].ip'")
        echo Keycloak: ${KEYCLOAK_IP}
        
        CLUSTER_MANAGER_IP=$(sudo_k8s "kubectl get services -n cluster-manager -o json | jq -r '.items[] | select(.metadata.name == \"traefik-k8s-lb\") | .status.loadBalancer.ingress[0].ip'")
        echo Cluster Manager: ${CLUSTER_MANAGER_IP}

        ACCESS_TOKEN=$(curl --silent --request POST http://${KEYCLOAK_IP}:8080/realms/master/protocol/openid-connect/token -H "Content-Type: application/x-www-form-urlencoded" --data "client_id=admin-cli&grant_type=password&username=admin&password=admin" | jq -r ".access_token")
        echo Access Token: ${ACCESS_TOKEN}

        # create realm, clientid and user
        # lxd suite my_curl
        
        HTTP_STATUS=$(curl --silent -o /dev/null -w "%{http_code}" --request GET http://${KEYCLOAK_IP}:8080/admin/realms/lxd-ui-realm --header "Authorization: Bearer ${ACCESS_TOKEN}")
        
        if [ ${HTTP_STATUS} -ne 200 ]; then
            
            HTTP_STATUS=$(curl --silent -o /dev/null -w "%{http_code}" --request POST http://${KEYCLOAK_IP}:8080/admin/realms --header "Content-Type: application/json" --header "Authorization: Bearer ${ACCESS_TOKEN}" --data "{ \"realm\" : \"lxd-ui-realm\", \"enabled\" : true }")
            echo "Create Realm ${HTTP_STATUS}"

            HTTP_STATUS=$(curl --silent -o /dev/null -w "%{http_code}" --request POST http://${KEYCLOAK_IP}:8080/admin/realms/lxd-ui-realm/clients --header "Content-Type: application/json" --header "Authorization: Bearer ${ACCESS_TOKEN}" --data "{ \"clientId\": \"lxd-ui-client\", \"name\": \"LXD UI\", \"enabled\": true, \"publicClient\": true, \"redirectUris\": [\"https://${CLUSTER_MANAGER_IP}/oidc/callback\"], \"attributes\": { \"oauth2.device.authorization.grant.enabled\": true } }")
            echo "Create Client ${HTTP_STATUS}"

            HTTP_STATUS=$(curl --silent -o /dev/null -w "%{http_code}" --request POST http://${KEYCLOAK_IP}:8080/admin/realms/lxd-ui-realm/users --header "Content-Type: application/json" --header "Authorization: Bearer ${ACCESS_TOKEN}" --data "{ \"username\": \"${USERNAME}\", \"email\": \"${EMAIL}\", \"enabled\": true, \"firstName\": \"${FIRST_NAME}\", \"lastName\": \"${LAST_NAME}\", \"credentials\": [ {\"type\": \"password\", \"value\": \"${PASSWORD}\", \"temporary\": false} ] }")
            echo "Create User ${HTTP_STATUS}"
        fi
    fi
}

cluster_manager() {
    
    if [[ "$(lxc project list -f json | jq "[.[].name] | any(. == \"${PROJECT}\")")" == "true" ]]; then
        if [[ "$(lxc_exec_user "juju list-models --format json | jq '[.models[].name] | any(. == \"admin/cluster-manager\")'")" == "true" ]]; then
                lxc_exec_user "juju deploy microcloud-cluster-manager-k8s --channel edge --trust" 
                lxc_exec_user "juju config microcloud-cluster-manager-k8s cluster-connector-domain=${CLUSTER_MANAGER_IP}"
                lxc_exec_user "juju config microcloud-cluster-manager-k8s cluster-connector-port=9001"
                lxc_exec_user "juju config microcloud-cluster-manager-k8s oidc-issuer=http://${KEYCLOAK_IP}:8080/realms/lxd-ui-realm"
                lxc_exec_user "juju config microcloud-cluster-manager-k8s oidc-client-id=lxd-ui-client"
                lxc_exec_user "juju config microcloud-cluster-manager-k8s oidc-audience="
    
                lxc_exec_user "juju integrate postgresql-k8s:database microcloud-cluster-manager-k8s"
                lxc_exec_user "juju integrate self-signed-certificates:certificates microcloud-cluster-manager-k8s"
                lxc_exec_user "juju integrate traefik-k8s:traefik-route microcloud-cluster-manager-k8s"
        fi
    fi
}

# ------------------------------------------------------------------------------

while getopts "d" arg; do
  case $arg in
    d)
      EXPECT_EXIST="true"
      ;;
  esac
done

project
vm_profile
group_and_permissions
identity
vms

k8s_cluster

if [[ "${MICROCEPH}" == "true" ]]; then
    microceph_cluster
    ceph_csi
else
    lxd_csi
fi

juju
cluster_manager_dependencies
keycloak
cluster_manager
