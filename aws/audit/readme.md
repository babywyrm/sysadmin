

##
#
https://github.com/shabarkin/aws-enumerator
#
##


##
## https://gist.github.com/joswr1ght/9512e7f591d4ba3758e3dd5359c0869b
##
```
#!/bin/bash
# https://stackoverflow.com/a/69728383/5089189 CC-BY-SA 4.0

function getUserIamPermissions() {
    export AWS_PAGER="";
    local _user="${1}";

    local outputManagedPolicies="";
    local outputUserPolicies="";
    local outputManagedGroupPolicies="";
    local outputGroupPolicies="";

    # Managed Policies Attached to the IAM User
    local _managedpolicies=$(aws iam list-attached-user-policies --user-name "${_user}" | jq -r '.AttachedPolicies[].PolicyArn';);
    for policy in ${_managedpolicies}; do
        local versionId=$(aws iam get-policy --policy-arn "${policy}" | jq -r '.Policy.DefaultVersionId';);
        outputManagedPolicies=$(aws iam get-policy-version --policy-arn "${policy}" --version-id "${versionId}";);
        printf "%s" "${outputManagedPolicies}";
    done;

    # Inline Policies on the IAM User
    local _userpolicies=$(aws iam list-user-policies --user-name "${_user}" | jq -r '.PolicyNames[]';);
    for policy in ${_userpolicies}; do
        outputUserPolicies=$(aws iam get-user-policy --user-name "${_user}" --policy-name "${policy}";);
        printf "%s" "${outputUserPolicies}";
    done;

    # Get all of the IAM User's assigned IAM Groups
    local _groups=$(aws iam list-groups-for-user --user-name "${_user}" | jq -r '.Groups[].GroupName';);
    for group in ${_groups}; do
        # Managed Policies Attached to the IAM Group
        local _managedgrouppolicies=$(aws iam list-attached-group-policies --group-name "${group}" | jq -r '.AttachedPolicies[].PolicyArn';);
        for policy in ${_managedgrouppolicies}; do
            local versionId=$(aws iam get-policy --policy-arn "${policy}" | jq -r '.Policy.DefaultVersionId';);
            outputManagedGroupPolicies=$(aws iam get-policy-version --policy-arn "${policy}" --version-id "${versionId}" | jq --arg arn "${policy}" '{"PolicyArn": $arn, "Policy": .}';);
            printf "%s" "${outputManagedGroupPolicies}";
        done;

        # Inline Policies on the IAM Group
        local _grouppolicies=$(aws iam list-group-policies --group-name "${group}" | jq -r '.PolicyNames[]';);
        for policy in ${_grouppolicies}; do
            outputGroupPolicies=$(aws iam get-group-policy --group-name "${group}" --policy-name "${policy}";);
            printf "%s" "${outputGroupPolicies}";
        done;
    done;
}

getUserIamPermissions "$1" | jq -s;
