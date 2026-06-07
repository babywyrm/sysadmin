##
## https://gist.github.com/matwerber1/6803e679e86a8419031956d45f6ea7ad
##

#! /bin/bash -i
set -e

# Constants
PROFILE_NICKNAME_FILE=".awsprofile.env"
AWS_CONFIG_FILE="$AWS_CONFIG_FILE"

# Variables
original_request="$1"
requested_profile=""
available_aws_profiles=()
declare -A available_nickname_mappings


populate_available_nickname_mappings() {
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        if [[ -n "$key" && -n "$value" ]]; then
            available_nickname_mappings["$key"]="$value"
        fi
    done < "$PROFILE_NICKNAME_FILE"

    if [ "${#available_nickname_mappings[@]}" -eq 0 ]; then
        echo "No mappings found in mapping file :("
        exit 1
    fi
}


set_target_profile_for_requested_nickname() {
    local nickname="$1"
    
    if [ "${#available_nickname_mappings[@]}" -eq 0 ]; then
        populate_available_nickname_mappings
    fi

    requested_profile="${available_nickname_mappings["$nickname"]}"

    if [ -z "$requested_profile" ]; then
        echo "Error: No profile mapping for nickname '$nickname' found in .awsprofile.env"
        print_available_profile_nicknames
        exit 1
    fi
}


populate_available_aws_profiles() {
    if [ -f "$AWS_CONFIG_FILE" ]; then
        while IFS= read -r line; do
            if [[ $line =~ \[profile\ (.*)\] ]]; then
                available_aws_profiles+=("${BASH_REMATCH[1]}")
            fi
        done < "$AWS_CONFIG_FILE"
    else
        echo "Error: could not find $AWS_CONFIG_FILE. Double-check that it exists on your host machine,"
        echo "is properly mounted in .devcontainer.json, and that you're running this script with a user"
        echo "that matches the home directory of the mounted file within this container."
        exit 1
    fi
}


print_available_aws_profiles() {
    if [ ${#available_aws_profiles[@]} -eq 0 ]; then
        populate_available_aws_profiles
    fi

    echo -e "\nAvailable profiles in ~/.aws/config:"
    echo "------------------------------------"
    for available_profile in "${available_aws_profiles[@]}"; do
        echo "$available_profile"
    done
}


print_available_profile_nicknames() {
    local max_length=0
    local key value

    # First, find the length of the longest nickname
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        if [[ -n "$key" && "$key" != "DEVCONTAINER_DEFAULT" ]]; then
            (( ${#key} > max_length )) && max_length=${#key}
        fi
    done < "$PROFILE_NICKNAME_FILE"

    # Adjust the second column's position
    local column_position=$((max_length + 30))

    echo -e "\nAvailable nicknames in $PROFILE_NICKNAME_FILE:\n"
    
    # Print column headers
    printf "%-${column_position}s %s\n" "Nickname (.awsprofile.env)" "AWS Profile (~/.aws/config)"
    # Print underline for column headers
    printf "%-${column_position}s %s\n" "$(printf '%0.s-' $(seq 1 $column_position))" "$(printf '%0.s-' {1..50})"

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        if [[ -n "$key" && -n "$value" && "$key" != "DEVCONTAINER_DEFAULT" ]]; then
            printf "%-${column_position}s %s\n" "$key" "$value"
        fi
    done < "$PROFILE_NICKNAME_FILE"
}



validate_profile_in_aws_config_file() {
    local profile_to_check="$1"

    populate_available_aws_profiles

    for available_profile in "${available_aws_profiles[@]}"; do
        if [ "$available_profile" == "$profile_to_check" ]; then
            return 0
        fi
    done

    echo "ERROR: Profile '$profile_to_check' does not exist in ~/.aws/config"
    print_available_aws_profiles
    exit 1
}


refresh_sso_token_if_needed() {
    local session_name="$1"
    response=$(aws sts get-caller-identity --profile "$requested_profile" --output json 2>&1 || echo "" 2>&1 )

    if [[ $response == *"The specified sso-session does not exist"* ]]; then
        echo -e "\nError: [profile $requested_profile] in your ~/.aws/config file is misconfigured.\n"
        echo "It contains a line 'sso_session = $session_name' which requires a corresponding section "
        echo "with a heading of '[sso-session $session_name]' that tells the AWS CLI the unique SSO endpoint"
        echo "needed to authenticate your session. This required section is not found. Refer to AWS documentation"
        echo "for additional guidance on configuring your AWS CLI for SSO (or, run 'aws sso configure')."
        exit 1
    
    elif [[ $response == *"configured to use SSO but is missing required configuration:"* ]]; then
        echo -e "\nError: [profile $requested_profile] in your ~/.aws/config file is misconfigured."
        echo -e $response
        echo ""
        exit 1

    elif [[ $response == *"Error loading SSO Token: Token for"* && $response == *"does not exist"* ]]; then
        echo -e "SSO token not present or expired. Initiating new login for session '$session_name'...\n"
        if [ -t 1 ]; then        
            aws sso login --sso-session "$session_name"
            if [ "$?" != 0 ]; then
                echo "You didn't login, exiting!"
                exit 1
            fi
        else
            echo "Not in a tty, gracefully exiting due to no active SSO login. "
            echo "Check that you're logged in via SSO or have permissions via IAM already set up."
            exit 1
        fi
    elif [[ $response == *"\"UserId\":" ]]; then
        echo "Reusing previously-cached unexpired SSO token."
    fi
}


get_modified_ps1_prompt_for_subshell() {

    local subshell_profile="$1"

    red=`tput setaf 1`
    green=`tput setaf 2`
    yellow=`tput setaf 3`
    reset=`tput sgr0`

    # Create prompt snippet that shows "(AWS 👉 <profile_name>)"
    AWS_PROFILE_PS1="\[${yellow}\](AWS 👉 $subshell_profile)\[${reset}\]"

    # Combine AWS prompt snippet with the PS1 prompt created as part of devcontainer 
    # feature that I happen to like -> ghcr.io/devcontainers/features/common-utils:2
    NEW_PS1=$(cat <<EOF
\[\]`export XIT=$? \
&& echo -n "${AWS_PROFILE_PS1} " \
&& [ ! -z "${GITHUB_USER}" ] && echo -n "\[\033[0;32m\]@${GITHUB_USER} " || echo -n "\[\033[0;32m\]\u " \
&& [ "$XIT" -ne "0" ] && echo -n "\[\033[1;31m\]➜" || echo -n "\[\033[0m\]➜"` \[\033[1;34m\]\w `\
if [ "$(git config --get devcontainers-theme.hide-status 2>/dev/null)" != 1 ] && [ "$(git config --get codespaces-theme.hide-status 2>/dev/null)" != 1 ]; then \
    export BRANCH=$(git --no-optional-locks symbolic-ref --short HEAD 2>/dev/null || git --no-optional-locks rev-parse --short HEAD 2>/dev/null); \
    if [ "${BRANCH}" != "" ]; then \
        echo -n "\[\033[0;36m\](\[\033[1;31m\]${BRANCH}" \
        && if [ "$(git config --get devcontainers-theme.show-dirty 2>/dev/null)" = 1 ] && \
            git --no-optional-locks ls-files --error-unmatch -m --directory --no-empty-directory -o --exclude-standard ":/*" > /dev/null 2>&1; then \
                echo -n " \[\033[1;33m\]✗"; \
        fi \
        && echo -n "\[\033[0;36m\]) "; \
    fi; \
fi`\[\033[0m\] $ \[\]
EOF
)
    echo "$NEW_PS1"
}

get_profile_type() {
    local profile_name=$1
    local profile_type=""
    local line
    local sso_session_pattern="sso_session ="
    local source_profile_pattern="source_profile ="

    while IFS= read -r line; do
        if [[ $line == "[profile $profile_name]" ]]; then
            profile_type="standalone"  # Default to standalone
            continue
        fi

        if [[ -n $profile_type ]]; then
            if [[ $line == $sso_session_pattern* ]]; then
                profile_type="sso"
                break
            elif [[ $line == $source_profile_pattern* ]]; then
                profile_type="chained"
                break
            elif [[ $line == "["* ]]; then
                break  # Reached next profile without finding a specific type
            fi
        fi
    done < "$AWS_CONFIG_FILE"

    echo $profile_type
}

get_root_profile() {
    local current_profile=$1
    local root_profile=""
    local is_sso_session=false
    
    while : ; do
        local profile_type=$(get_profile_type "$current_profile")
        case $profile_type in
            "sso")
                root_profile=$current_profile
                is_sso_session=true
                break
                ;;
            "standalone")
                root_profile=$current_profile
                is_sso_session=false
                break
                ;;
            "chained")
                #echo "testing chained $current_profile"
                local source_profile=$(grep -A 10 "^\[profile $current_profile\]" "$AWS_CONFIG_FILE" | awk -F "[[:space:]]*=[[:space:]]*" '/^\[/ && !/^\[profile '"$current_profile"'\]/ {exit} $1 == "source_profile" {print $2; exit}')
                current_profile=${source_profile// /}  # Trim spaces
                
                ;;
            *)
                echo "Unknown profile type or profile not found: $current_profile" >&2
                return 1
                ;;
        esac
    done
    echo $current_profile
}


get_sso_session_name_for_sso_profile() {
    local profile="$1"
    sso_session_name=$(awk -v profile="[profile $profile]" -v found=0 '
    {
        if ($0 ~ /^\[profile / || $0 ~ /^\[sso-session /) {
            found=($0 == profile)
        } else if (found && $0 ~ /^sso_session = /) {
            split($0, arr, "= ")
            print arr[2]
            exit
        }
    }' "$AWS_CONFIG_FILE")

    [ -n "$sso_session_name" ] && echo "$sso_session_name" || return 1
}

validate_sts_caller_identity_response() {
    local response="$1"
    if [[ $response == *"\"UserId\":" ]]; then
        return 0
    else
        echo -e "\nError: could not validate the profile you've requested. Please review your ~/.aws/config file carefully."
        echo "If this profile uses or is chained from an AWS SSO role, try running 'aws sso login'. "
        echo -e "\nResponse from 'aws sts get-caller-identity':"
        echo $response
        exit 1
    fi
}


switch_profile_per_user_request() {
    local original_request="$1"


    if [ -f "$PROFILE_NICKNAME_FILE" ]; then
        requested_nickname="$original_request"
        set_target_profile_for_requested_nickname "$requested_nickname"
    else
        requested_profile="$original_request"
    fi

    validate_profile_in_aws_config_file $requested_profile
    root_profile=$(get_root_profile "$requested_profile")
    root_profile_type=$(get_profile_type "$root_profile")
    requested_profile_type=$(get_profile_type "$requested_profile")

    if [ $requested_profile_type == "chained" ]; then
        echo "Requested profile $requested_profile is a chained role that is ultimately assumed from parent ${root_profile_type} profile $root_profile"
    fi
    
    if [ $root_profile_type == "sso" ]; then
        if sso_session_name=$(get_sso_session_name_for_sso_profile "$root_profile_type"); then
            refresh_sso_token_if_needed "$sso_session_name"
        fi
    fi
    
    response=$(aws sts get-caller-identity --profile "$profile" --output json 2>&1 || echo "" 2>&1 )
    validate_sts_caller_identity_response "$response"

    aws_profile_account=$(echo "$sts_identity_of_target_profile" | jq -r '.Account')
    aws_profile_arn=$(echo "$sts_identity_of_target_profile" | jq -r '.Arn')
    echo -e "\nOpening new shell for profile $requested_profile:"
    echo "----------------------------------------------------------------------------------------------------------"
    echo "account=$aws_profile_account"
    echo "arn=$aws_profile_arn"
    echo ""
    echo "('exit' command will return you to prior shell)"
    echo ""

    AWS_DEFAULT_PROFILE="$requested_profile" PS1=$(get_modified_ps1_prompt_for_subshell $requested_profile) bash --norc
}

set_devcontainer_default_profile() {
   
    # Check if file has a key-value line for "DEVCONTAINER_DEFAULT=<target_profile>"
    local default_devcontainer_profile

    if [ -f "$PROFILE_NICKNAME_FILE" ]; then
        if grep -q "DEVCONTAINER_DEFAULT=" "$PROFILE_NICKNAME_FILE"; then
            # Store the value in variable $default_devcontainer_profile
            default_devcontainer_profile=$(grep "DEVCONTAINER_DEFAULT=" "$PROFILE_NICKNAME_FILE" | cut -d '=' -f2)

            echo "== CONFIGURING DEFAULT AWS PROFILE FOR DEV CONTAINER"
            echo "  echo \"export AWS_DEFAULT_PROFILE=$default_devcontainer_profile\" >> ~/.profile"
            echo "  ----> Use .awsprofile.env to change or disable this behavior"

            validate_profile_in_aws_config_file "$default_devcontainer_profile"

            # 5. Add export to profile configuration file
            echo "export AWS_DEFAULT_PROFILE=$default_devcontainer_profile" >> ~/.profile

            # 6. Store result of get_modified_ps1_prompt_for_subshell in NEW_DEFAULT_PS1
            local NEW_DEFAULT_PS1=$(get_modified_ps1_prompt_for_subshell "$default_devcontainer_profile")

            # 7. Modify ~/.bashrc
            {
                echo "PS1='$NEW_DEFAULT_PS1'"
                echo "export AWS_DEFAULT_PROFILE=\"$default_devcontainer_profile\""
            } >> ~/.bashrc
        fi
    fi

}

display_help() {
    echo "Usage: aws-profile <AWS profile name | profile nickname | --set_devcontainer_default>"
    echo
    echo "This script supports three modes of operation:"
    echo "1. aws-profile <AWS profile name>"
    echo "   Use when the local project repository does not contain .awsprofile.env."
    echo "   The argument is the name of a profile from ~/.aws/config."
    echo
    echo "2. aws-profile <profile nickname>"
    echo "   Use when the local project repository contains .awsprofile.env."
    echo "   The argument is a nickname defined in .awsprofile.env."
    echo
    echo "3. aws-profile --set_devcontainer_default"
    echo "   Sets the default AWS profile for devcontainer."
    echo "   Requires DEVCONTAINER_DEFAULT nickname in .awsprofile.env."
    echo
    echo "--help  Display this help and exit."
}


case "$1" in
    --help)
        display_help
        ;;
    --set_devcontainer_default)
        # Handling the --set_devcontainer_default case
        set_devcontainer_default_profile
        ;;
    *)
        # Handling AWS profile name or nickname
        if [[ -z "$1" ]]; then
            echo "Error: No argument provided."
            display_help
            exit 1
        fi
       
        switch_profile_per_user_request "$1"
        ;;
esac

##
##

function aws-sso-access-token() {
    find "$HOME/.aws/sso/cache" -type f ! -name 'botocore*' -exec jq -r '.accessToken' {} \; | head -n1
}

function aws-sso-list-accounts() {
    aws sso list-accounts --access-token "$(aws-sso-access-token)" "$@"
}

function aws-sso-list-account-roles() {
    aws sso list-account-roles --access-token "$(aws-sso-access-token)" "$@"
}

function aws-sso-profile-template() {
    if [ "$#" -ne 6 ]; then
        return 1
    fi
    profile_name=$1
    sso_start_url=$2
    sso_region=$3
    sso_account_id=$4
    sso_role_name=$5
    default_region=$6

    cat << EOF
[profile $profile_name]
sso_start_url   = $sso_start_url
sso_region      = $sso_region
sso_account_id  = $sso_account_id
sso_role_name   = $sso_role_name
region          = $default_region
EOF
}

function aws-sso-generate-profiles-config() {
    sso_start_url=$1
    sso_region=$2
    cli_default_region=$2

    if [ "$#" -ne 2 ]; then
        return 1
    fi

    aws-sso-list-accounts --output json | jq '.accountList[]' -rc | while read -r account; do
        accountId="$(echo "$account" | jq -rc '.accountId')"
        accountName="$(echo "$account" | jq -rc '.accountName | ascii_downcase | gsub(" "; "-")')"

        aws-sso-list-account-roles --output json --account-id "$accountId" | jq '.roleList[].roleName' -rc | while read -r roleName; do
            aws-sso-profile-template "$accountName-$roleName" "$sso_start_url" "$sso_region" "$accountId" "$roleName" "$cli_default_region"
            echo
        done
    done
}
