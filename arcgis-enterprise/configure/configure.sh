#!/bin/bash

PROG=$(basename "$0")
CWD=$(cd "$(dirname "$0")" && pwd)
CONTEXT=${CONTEXT:-arcgis}
K8S_NAMESPACE=${K8S_NAMESPACE:-arcgis}
SITE_URL=""
OS="$(uname -s)"

RESOURCES=$(cd "${CWD}/../../.install/resources" && pwd)
COMMON="${RESOURCES}/scripts/common.sh"
TEMP_DIR="${RESOURCES}/tmp"
CONFIGURE_PROPERTIES_TEMPLATE="${RESOURCES}/templates/configure.properties.template"
CONFIGURE_PROPERTIES=""
STORAGE_JSON_TEMPLATE="${RESOURCES}/templates/storage.json.template"
STORAGE_JSON="${TEMP_DIR}/configure.storage.json"
USER_MANAGED_DATASTORES=""

DEBUG_LOG="${TEMP_DIR}/configure.debug.$$.log"
declare -a MESSAGE_LIST=()

# Flags
SILENT=false
VERBOSE=false
DEBUG=false

# wait flags
SLEEP_SECONDS=10
MAX_MINUTES=30
ABORTED=false

VERSION_TAG=""

# To pick up jq
export PATH="${RESOURCES}/bin/${OS}:${PATH}"


usage()
{
  cat <<EOF

  This script performs three tasks:

  * Verifies configure.properties values are valid
  * Creates storage JSON based on provided storage properties
  * Creates Enterprise Organization

  USAGE: % ./${PROG} [options] -f user_properties>

  OPTIONS:

    -h                   - Usage
    -f <properties_file> - Use specified properties file (REQUIRED)
    -v                   - Show verbose output
    -s                   - Create organization without prompting for input
    -u <user_datastores> - Specify user-managed data stores JSON file

  EXAMPLES:

  * Configure using specified properties file

      % ./${PROG} -f my.properties

  * Configure silently

      % ./${PROG} -s -f my.properties

  * Configure with user-managed data stores

      % ./${PROG} -f my.properties -u /path/to/my_data_stores.json

EOF
  exit 0
}

init_temp_dir()
{
  [ "$HELM_DEPLOY" = true ] && {
    TEMP_DIR="/arcgistmp"
    STORAGE_JSON="${TEMP_DIR}/configure.storage.json"
    DEBUG_LOG="${TEMP_DIR}/configure.debug.$$.log"
  }
}

cleanup()
{
  [ -f "$STORAGE_JSON" ] && rm -f "$STORAGE_JSON"
  [ "$DEBUG" = false ] && rm -f "${TEMP_DIR}"/configure.debug.*
}

banner()
{
  draw_line
  text_bold
  if [ -n "$VERSION_TAG" ]; then
    print_center "${ARCGIS_VERSION}"
    print_center "Configure ${PRODUCT_NAME} ${PRODUCT_VERSION} (${VERSION_TAG})"
  else
    print_center "${ARCGIS_VERSION}"
    print_center "Configure ${PRODUCT_NAME} ${PRODUCT_VERSION}"
  fi
  text_normal
  draw_line
}

fail()
{
  echo ""
  printf "%sERROR%s: $1" "${fg_red}" "${txt_reset}"
  echo ""
  exit 1
}

info_exit()
{
  echo ""
  printf "%sINFO%s: $1" "${fg_cyan}" "${txt_reset}" | fmt
  echo ""
  exit 0
}

exit_msg()
{
  echo ""
  echo "$1" | fmt
  echo ""
  exit 0
}

echo_v()
{
  [ "$VERBOSE" = true ] || [ "$DEBUG" = true ] && echo "$1"
}

debug()
{
  [ "$DEBUG" = false ] && return

  local func="$1"
  local now=$(date +"%Y-%m-%d %H:%M:%S" | xargs)

  shift
  echo "----------------------------------------------------" >> "$DEBUG_LOG"
  echo "${func} ${now}:" >> "$DEBUG_LOG"
  echo -e "$@" >> "$DEBUG_LOG"
  echo "----------------------------------------------------" >> "$DEBUG_LOG"
}

clear_current_line()
{
  if [ "$HAS_TTY" = true ]; then
    echo -en "\033[2K\r"
  else
    printf "%65s\r" '' ""
  fi
}

get_version_tag()
{
  local tag=$(get_admin_version_tag)

  [ -n "$tag" ] && VERSION_TAG="$tag"
}


# ----------------------------------------------
# Sanity check
# ----------------------------------------------

check_jq()
{
  jq --version > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    fail "The jq JSON parser was not found or failed to run."
  fi
}


sanity_check()
{
  [ ! -d "${RESOURCES}" ] && fail "Resources folder not found: ${RESOURCES}"
  [ ! -d "${TEMP_DIR}" ] && fail "Local tmp dir not found: ${TEMP_DIR}"
  [ ! -f "${COMMON}" ] && fail "Common script not found: ${COMMON}"
  [ ! -f "${CONFIGURE_PROPERTIES_TEMPLATE}" ] && fail "Configure properties template not found: ${CONFIGURE_PROPERTIES_TEMPLATE}"
  [ ! -f "${STORAGE_JSON_TEMPLATE}" ] && fail "Storage json template not found: ${STORAGE_JSON_TEMPLATE}"
}

validation_check()
{
  header "Running Validation Checks..."
  check_configure_properties
  check_jq
  read_properties_file
  check_properties_vars
  validate_encryption
  validate_storage_classes
  validate_architecture_profile
}


# ----------------------------------------------
# Properties file handling
# ----------------------------------------------
check_configure_properties()
{
  if [ ! -f "${CONFIGURE_PROPERTIES}" ]; then
    usage

    exit 0
  fi
}

validate_security_question_index()
{
  local -i value=$1
  local ret=0

  if [ $value -lt 1 ] || [ $value -gt 14 ]; then
    ret=1
  fi

  [ $ret -eq 0 ]
}

validate_storage_classes()
{
  echo "Checking storage classes..."

  local error_count=0
  local invalid_storage_classes=()
  while read line
  do
    local sc=${line/*=}

    is_storage_class_valid "$sc"
    if [ $? -ne 0 ]; then
      ((error_count++))
      invalid_storage_classes+=("$line
      ")
    fi
  done < <(cat "${CONFIGURE_PROPERTIES}" | grep "_STORAGE_CLASS=" | sed 's/"//g')

  if [ $error_count -gt 0 ]; then
    echo ""
    echo "The following storage classes could not be found:"
    echo ""
    for v in "${invalid_storage_classes[@]}"
    do
      echo "    - $v"
    done
    echo ""
    exit 1
  fi
}
validate_architecture_profile()
{
  echo "Checking architecture profile..."

  [ -z "$SYSTEM_ARCH_PROFILE" ] && fail "You need to set SYSTEM_ARCH_PROFILE in your properties file."

  if [ "$SYSTEM_ARCH_PROFILE" != "development" ] &&
     [ "$SYSTEM_ARCH_PROFILE" != "standard-availability" ] &&
     [ "$SYSTEM_ARCH_PROFILE" != "enhanced-availability" ]; then
    fail "Your SYSTEM_ARCH_PROFILE needs to be set to 'development', 'standard-availability' or 'enhanced-availability'."
  fi
}

validate_encryption()
{
  [ -z "${ENCRYPTION_KEYFILE}" ] && fail "Variable ENCRYPTION_KEYFILE is not defined."
  [ ! -f "${ENCRYPTION_KEYFILE}" ] && fail "Encryption keyfile not found: ${ENCRYPTION_KEYFILE}"

  if ! $(can_decrypt_aes256_string "$ADMIN_PASSWORD" "$ENCRYPTION_KEYFILE") ; then
    echo ""
    printf "%sERROR%s: Failed to decrypt admin password.\n" "${fg_red}" "${txt_reset}"
    echo ""
    echo "Create an encrypted password using the following command:"
    echo ""
    echo "    % echo \"my.admin.password\" | ../password-encrypt/password-encrypt.sh -f \"${ENCRYPTION_KEYFILE}\""
    echo ""
    echo "Then set ADMIN_PASSWORD to that encrypted value."
    echo ""
    exit 1
  fi
}

check_properties_vars()
{
  local -a unset_vars=()
  local -a errors=()

  echo "Checking property values..."

  # Check for unset variables
  while IFS= read line
  do
    local var=$(echo "$line" | cut -d= -f1)
    local val=${!var}

    # Exceptions (can be null)
    if [ "$var" = "REGISTERED_FOLDER_PATHS" ] ||
       [ "$var" = "LOG_SETTING" ]; then
      continue
    fi

    [ -z "$val" ] && unset_vars+=("$var")
  done < <(cat "${CONFIGURE_PROPERTIES}" | grep -Ev "^#|^$")

  if [ ${#unset_vars} -gt 0 ]; then
    echo ""
    echo "The following variables need to be set:"
    echo ""
    for v in "${unset_vars[@]}"
    do
      echo "    - $v"
    done
    echo ""
    exit 1
  fi

  # Validate some known variables
  [ ! -f "$LICENSE_FILE_PORTAL" ] && errors+=("Portal license file not found: $LICENSE_FILE_PORTAL")
  [ ! -f "$LICENSE_FILE_SERVER" ] && errors+=("Server license file not found: $LICENSE_FILE_SERVER")

  # Check "SECURITY_QUESTION_INDEX
  if ! validate_security_question_index "$SECURITY_QUESTION_INDEX" ; then
    errors+=("SECURITY_QUESTION_INDEX should be an integer between 1 and 14")
  fi

  if [ ${#errors} -gt 0 ]; then
    echo ""
    echo "The following errors were detected in your property file:"
    echo ""
    for e in "${errors[@]}"
    do
      echo "    - $e"
    done
    echo ""
    exit 1
  fi
}

replace_json_placeholders()
{
  echo "Creating storage JSON..."
  while IFS= read line
  do
    var=$(echo "$line" | cut -d= -f1)
    val=${!var}

    [ -z "$val" ] && continue

    echo_v "  ${var} = ${val}"

    edit_in_file 's^<'${var}'>^'"${val}"'^g' "${STORAGE_JSON}"

  done < <(cat "${CONFIGURE_PROPERTIES}" | grep -Ev "^#|^$")
}

handle_labels()
{
  local prefix="$1"
  local place_holder="$2"
  local file="$3"
  local -a var_list=()
  local tmp_file="${TEMP_DIR}/configure.labels.$$.tmp"

  echo_v "  Setting labels for $place_holder..."

  found=$(cat "${CONFIGURE_PROPERTIES}" | grep -Ev "^#|^$" | grep "$prefix")
  [ -z "$found" ] && fail "Property $prefix not found in $(basename ${CONFIGURE_PROPERTIES}).  Is this file up to date?"

  # Create var_list of label variables
  while IFS= read line
  do
    local value_string="$(echo "$line" | cut -d= -f2- | sed 's/"//g')"

    if [ -n "$value_string" ]; then
      var_list+=("$value_string")
    fi
  done < <(cat "${CONFIGURE_PROPERTIES}" | grep -Ev "^#|^$" | grep "$prefix")

  local len=${#var_list[@]}

  rm -f "$tmp_file"

  # Convert var_list into key/value JSON format
  for i in "${!var_list[@]}"
  do
    local key="${var_list[$i]%%:*}"
    local val="${var_list[$i]##*:}"

    if [ $i -lt $(($len - 1)) ]; then
      echo "        \"$key\": \"$val\"," >> "$tmp_file"
    else
      echo "        \"$key\": \"$val\"" >> "$tmp_file"
    fi
  done

  # Create bash variable with hard \n's in it
  local data=$(cat "$tmp_file")
  data=${data//$'\n'/\\n}

  # Replace the labels placeholder with json list
  edit_in_file "s^${place_holder}^${data}^g" "$file"

  rm -f "$tmp_file"
}

create_storage_json()
{
  cp -p "${STORAGE_JSON_TEMPLATE}" "${STORAGE_JSON}"
  [ $? -ne 0 ] && "Failed to copy JSON storage template: ${STORAGE_JSON_TEMPLATE}"

  replace_json_placeholders

  handle_labels "RELATIONAL_STORAGE_LABEL" "<RELATIONAL_LABELS>" "${STORAGE_JSON}"
  handle_labels "OBJECT_STORAGE_LABEL" "<OBJECT_LABELS>" "${STORAGE_JSON}"
  handle_labels "MEMORY_STORAGE_LABEL" "<MEMORY_LABELS>" "${STORAGE_JSON}"
  handle_labels "QUEUE_STORAGE_LABEL" "<QUEUE_LABELS>" "${STORAGE_JSON}"
  handle_labels "INDEXER_STORAGE_LABEL" "<INDEXER_LABELS>" "${STORAGE_JSON}"
  handle_labels "SHARING_STORAGE_LABEL" "<SHARING_LABELS>" "${STORAGE_JSON}"
  handle_labels "PROMETHEUS_STORAGE_LABEL" "<PROMETHEUS_LABELS>" "${STORAGE_JSON}"

  echo_v "  STORAGE_JSON = $STORAGE_JSON"
}

minify_json_file()
{
  local file="$1"

  [ ! -f "$file" ] && fail "JSON file not found: $file"

  jq -rc < "${file}"
}


# ----------------------------------------------
# Create Site/Organization
# ----------------------------------------------
is_pod_running()
{
  local pod="$1"
  local output=""
  output=$(kubectl get pods -n $K8S_NAMESPACE -o name | grep -w $pod)
  [ -n "$output" ] && true || false
}

is_storage_class_valid()
{
  local storage_class="$1"
  local output=""
  output=$(kubectl get sc -n $K8S_NAMESPACE | grep -w "$storage_class")
  [ -n "$output" ] && true || false
}

is_admin_pod_running()
{
  is_pod_running "rest-administrator-api"
}

secs_to_min_sec()
{
  local secs="$1"
  printf "%02dm:%02ds" "$(($secs%3600/60))" "$(($secs%60))"
}

get_admin_pod_name()
{
  local name=$(kubectl get pods -n $K8S_NAMESPACE  | grep rest-administrator-api | awk '{print $1}')
  echo "$name"
}

get_admin_version_tag()
{
  local admin_pod=$(get_admin_pod_name)
  local tag=""
  tag=$(kubectl get pod $admin_pod -n $K8S_NAMESPACE -o jsonpath="{.spec.containers[1].image}" | cut -d: -f2)
  echo "$tag"
}

check_admin_url()
{
  echo "Checking organization URL..."

  # Check host
  curl -o /dev/null -k -s "${SITE_URL}"
  if [ $? -ne 0 ]; then
    echo ""
    echo "Failed to connect to host/url: ${SITE_URL}"
    echo ""
    echo "Check the ARCGIS_ENTERPRISE_FQDN for a valid FQDN in your properties file."

    fail "Failed to validate organization URL."
  fi

  # Host is OK, check endpoint
  local http_code=0
  http_code=$(curl -o /dev/null -k -s -w "%{http_code}\n" "${SITE_URL}/${CONTEXT}/admin")

  http_code=$(printf "%d" "$http_code")  # Strip leading 000 zeros

  if [ $http_code -ge 200 ] && [ $http_code -lt 400 ]; then
    return
  fi

  echo ""
  echo "Error validating organization URL: ${SITE_URL}/${CONTEXT}/admin"
  echo "Error code from server: $http_code"
  echo ""
  echo "Check your properties file for valid CONTEXT and ARCGIS_ENTERPRISE_FQDN."

  fail "Failed to validate organization URL."
}


get_token()
{

  if ! is_token_needed ; then
    debug "$FUNCNAME" "Token is not needed yet"
    return
  fi

  local token=""

  local admin_user="${ADMIN_USERNAME}"
  local admin_pass="$(get_decrypted_aes256_string "$ADMIN_PASSWORD" "$ENCRYPTION_KEYFILE")"

  local cmd="curl -X POST -s --insecure \
             -F 'username=${admin_user}' \
             -F 'password=${admin_pass}' \
             -F 'client=referer' \
             -F 'expiration=60' \
             -F 'f=pjson' \
             -F 'referer=${SITE_URL}/${CONTEXT}' \
             \"${SITE_URL}/${CONTEXT}/sharing/rest/generateToken\""

  debug "$FUNCNAME" "req=$cmd"

  res=$(eval ${cmd})

  debug "$FUNCNAME" "res=$res"

  # A token will only be available when a site it up
  echo "$res" | jq -r '.token' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    token=$(echo "$res" | jq -r '.token')
  fi

  echo "$token"
}

# Hit the admin endpoint and look for an error
#
# {
#   "error" : {
#     "code" : 499,
#     "message" : "Token Required.",
#     "details" : null
#   }
# }
is_token_needed()
{
  local url="${SITE_URL}/${CONTEXT}/admin?f=json"
  local res=""
  local code=""

  res=$(curl -s --insecure "$url")

  code=$(echo "$res" | jq -r -e '.error.code')
  [ "$code" = "499" ]
}

# get_site_status() - Query for global site status
# {
#    . . .
#    "currentVersion": 10.9,
#    "status": {
#	    . . .
#        "state": "in_progress",
#        "message": "Creating a new organization."
#    },
#}
# NOTE: message won't exist if state=not_configured
# state = not_configured(0), in_progress(1), configured(2), failed(3), ready(4)
#
get_site_status()
{
  local token=""
  local state=""
  local message=""
  local url="${SITE_URL}/${CONTEXT}/admin?f=json"

  token=$(get_token)

  if [ -n "$token" ]; then
    url="${SITE_URL}/${CONTEXT}/admin?f=json&token=$token"
  fi

  debug "$FUNCNAME" "\ncurl -s --insecure \"$url\""

  res=$(curl -s --insecure "$url")

  [ -n "$res" ] && {

    debug "$FUNCNAME" "res = ${res}"

    state=$(echo $res | jq -r '.status.state')

    if [ "$state" != "not_configured" ]; then
      message=$(echo $res | jq -r '.status.message')
    fi
  }

  echo "${state}|${message}"
}

# get_stages_list() - Just retrieve the stages[] array:
#
#    "status": {
#        "stages": [
#            {
#               "lastUpdated": 1612473621303,
#                "name": "Configuration Store",
#                "state": "completed"
#            },
#            {
#                "lastUpdated": 1612473704542,
#                "name": "Relational Store",
#                "state": "completed"
#            },
#            {
#                "lastUpdated": 1612473637963,
#                "name": "Queue Store",
#                "state": "in_progress"
#            },
#            . . .
# The stages will only be available once configure is initiated.
#
# The result returns will be a long string of "name1:state1,name2:state2,name3:state3, etc..."
# which will be parsed below in poll_site_status().
get_stages_list()
{
  local token=""
  local stages=""
  local url="${SITE_URL}/${CONTEXT}/admin?f=json"

  token=$(get_token)

  if [ -n "$token" ]; then
    url="${SITE_URL}/${CONTEXT}/admin?f=json&token=$token"
  fi

  debug "$FUNCNAME" "\ncurl -s --insecure \"$url\""

  local res=$(curl -s --insecure "$url")

  [ -n "$res" ] && {

    debug "$FUNCNAME" "res = ${res}"

    stages=$(echo $res | jq -r '.status.stages[] | [.name, .state] | @csv' | sed 's/,/:/g' | sed 's/"//g' | paste -sd ',')
  }

  echo "${stages}"
}

get_registered_folder_paths()
{
  local -a paths=()

  if [ -z "$REGISTERED_FOLDER_PATHS" ]; then
    echo "{\"paths\":[]}"
    return
  fi

  local json="{\"paths\":["

  # Split comma-separated path string into an array, stripping spaces
  local paths_string="$(echo "$REGISTERED_FOLDER_PATHS" | sed 's/, /,/g')"
  IFS=',' read -r -a paths <<< "$paths_string"
  [ $? -ne 0 ] && fail "Failed to parse registered paths list."

  for path in "${paths[@]}"
  do
    json="${json}\"${path}\","
  done

  json="${json%?}"    # strip last comma
  json="${json}]}"    # append last bit

  echo "$json"
}

get_log_settings()
{
  local json="{\"logLevel\":"

  json="${json}\"${LOG_SETTING}\""
  json="${json}}"
  echo "${json}"
}

get_user_managed_datastores()
{
  local json="[]"

  if [ -n "$USER_MANAGED_DATASTORES" ]; then
    [ ! -f "$USER_MANAGED_DATASTORES" ] && fail "Could not find userManagedStores file: $USER_MANAGED_DATASTORES"

    # Redefine it based on .json contents
    json=$(minify_json_file "$USER_MANAGED_DATASTORES")
  fi

  echo "$json"
}

validate_portal_license()
{
  echo "Checking portal license..."

  local base_url="${SITE_URL}/${CONTEXT}/admin/orgs/0123456789ABCDEF/license/validateLicense"

  local cmd="curl -s --insecure \
    -F 'file=@${LICENSE_FILE_PORTAL}' \
    -F 'listAdministratorUserTypes=true' \
    -F 'f=pjson' \
    ${base_url}"

  debug "$FUNCNAME" "\n$cmd"

  res=$(eval $cmd)

  echo_v "res=$res"

  echo "$res" | jq -r -e '.error.message' > /dev/null 2>&1

  if [ $? -eq 0 ]; then
     message=$(echo $res | jq -r '.error.message')
     fail "$message"
  fi
}

get_configure_curl_cmd()
{
  local license_file_portal="${LICENSE_FILE_PORTAL}"
  local license_file_server="${LICENSE_FILE_SERVER}"
  local storage_json=$(minify_json_file "${STORAGE_JSON}")

  local admin_user="${ADMIN_USERNAME}"
  local admin_pass="$(get_decrypted_aes256_string "$ADMIN_PASSWORD" "$ENCRYPTION_KEYFILE")"

  local folder_paths="$(get_registered_folder_paths)"

  local log_settings="$(get_log_settings)"

  local user_managed_datastores="$(get_user_managed_datastores)"

  local cmd="curl -s --insecure \
    -F 'username=${admin_user}' \
    -F 'password=${admin_pass}' \
    -F 'email=${ADMIN_EMAIL}' \
    -F 'fullName=${ADMIN_FIRST_NAME} ${ADMIN_LAST_NAME}' \
    -F 'securityQuestionIdx=${SECURITY_QUESTION_INDEX}' \
    -F 'securityQuestionAns=${SECURITY_QUESTION_ANSWER}' \
    -F 'userLicenseTypeId=${LICENSE_TYPE_ID}' \
    -F 'licenseFile=@${license_file_portal}' \
    -F 'serverLicenseFile=@${license_file_server}' \
    -F 'volumesConfig=${storage_json}' \
    -F 'systemArchitectureProfile={\"name\":\"${SYSTEM_ARCH_PROFILE}\"}' \
    -F 'folderPathsToRegister=${folder_paths}' \
    -F 'logSettings=${log_settings}' \
    -F 'userManagedStores=${user_managed_datastores}' \
    -F 'f=pjson' \
    ${SITE_URL}/${CONTEXT}/admin/configure"

  echo "${cmd}"
}

create_site()
{
  local cmd=$(get_configure_curl_cmd)

  echo ""
  draw_line

  debug "$FUNCNAME" "\ncmd=$cmd"
  echo_v "cmd=$cmd"

  # Execute the curl and get the json response
  res=$(eval $cmd)

  [ -n "$res" ] && {

    debug "$FUNCNAME" "res = ${res}"
    echo_v "res=$res"

    # check for an error and fail
    echo "$res" | jq -r -e '.error.message' > /dev/null 2>&1
    [ $? -eq 0 ] && {
      local message=$(echo "$res" | jq -r '.error.message')

      fail "$message"
    }
  }

}

is_site_configured()
{
  local state=$(get_site_status | awk -F "|" '{print $1}')

  # not_configured, in_progress, configured, failed, ready
  #
  # We can only run configure when the state = not_configured
  [ "$state" = "ready" ] || [ "$state" = "configured" ]
}

is_configure_in_progress()
{
  local state=$(get_site_status | awk -F "|" '{print $1}')
  [ "$state" = "in_progress" ]
}

is_message_in_list()
{
  local msg="$1"
  local found=1

  for i in "${MESSAGE_LIST[@]}"
  do
    if [ "$i" = "$msg" ]; then
      found=0
      break
    fi
  done

  [ $found -eq 0 ]
}

print_status_line()
{
  local name="$1"
  local state="$2"
  local status_color="${fg_green}"

  [ "$state" = "failed" ] && status_color="${fg_red}"

  printf -- "- %-32s %s%s%s\n" "$name" "$status_color" "$state" "${txt_reset}"
}

exit_with_ctrlc_message()
{
  echo ""
  echo ""
  echo "The configure process will continue to run on the server. If you run this"
  echo "script again while the process is still running, it will reflect the"
  echo "current status."
  echo ""
  exit 0
}

poll_site_status()
{
  echo ""
  echo "Creating an organization."
  echo ""

  trap exit_with_ctrlc_message SIGINT

  #set -x
  while :
  do
    local res=""
    local current_stages=()
    local org_state=""
    local stages=""

    res=$(get_site_status)

    org_state=$(echo $res | awk -F "|" '{print $1}')
    stages=$(get_stages_list)

    # Create current_stages array
    while IFS=, read line
    do
      [ ${#line} -gt 0 ] && current_stages+=("$line")
    done < <(echo "$stages" | tr "," "\n")

    for msg in "${current_stages[@]}"
    do
      local name=$(echo "$msg" | awk -F: '{print $1}' | xargs)
      local state=$(echo "$msg" | awk -F: '{print $2}' | xargs)

      if [ "$state" == "completed" ] || [ "$state" == "failed" ]; then
        if ! is_message_in_list "$name" ; then

          MESSAGE_LIST+=("$name")

          clear_current_line

          print_status_line "$name" "$state"

        fi
      fi
    done

    sleep 5

    [ "$HAS_TTY" = true ] &&  printf "%s.%s" "${fg_green}" "${txt_reset}" || printf "."

    # not_configured, in_progress, configured, failed, ready
    if [ "$org_state" = "not_configured" ] || [ "$org_state" = "failed" ] || [ "$org_state" = "ready" ]; then
      clear_current_line
      break
    fi

  done

  echo ""

}

show_success()
{
  local message="$1"

  draw_line
  echo "                           ${fg_green}S U C C E S S !${txt_reset}"
  draw_line
  echo "${message}"
  echo ""
  echo "You can use the URLs below to access your "
  echo "${PRODUCT_NAME} deployment."
  echo ""
  local portal_url="${SITE_URL}/${CONTEXT}/home"
  local manager_url="${SITE_URL}/${CONTEXT}/manager"
  echo -e "Enterprise portal URL:\n\n\t${portal_url}"
  echo ""
  echo -e "Manager URL:\n\n\t${manager_url}"
  echo ""
}

read_properties_file()
{
  local properties_file="$CONFIGURE_PROPERTIES"

  [ ! -f "$properties_file" ] && fail "Properties file not found ($properties_file).  Cannot determine site URL."

  . "$properties_file"

  SITE_URL="https://${ARCGIS_ENTERPRISE_FQDN}"

}

prompt_user()
{
  echo ""
  echo "Current deployment properties:"
  echo ""
  echo "  CONFIGURE PROPERTIES FILE: $CONFIGURE_PROPERTIES"
  echo ""
  echo "  PORTAL LICENSE FILE:       $LICENSE_FILE_PORTAL"
  echo "  SERVER LICENSE FILE:       $LICENSE_FILE_SERVER"
  echo ""
  echo "  USERNAME:                  $ADMIN_USERNAME"
  echo "  PASSWORD:                  $ADMIN_PASSWORD"
  echo "  EMAIL:                     $ADMIN_EMAIL"
  echo "  FIRST NAME:                $ADMIN_FIRST_NAME"
  echo "  LAST NAME:                 $ADMIN_LAST_NAME"
  echo ""
  echo "  SYSTEM ARCHITECTURE:       $SYSTEM_ARCH_PROFILE"
  echo ""
  echo "  NAMESPACE:                 $K8S_NAMESPACE"
  echo "  ARCGIS ENTERPRISE FQDN:    $ARCGIS_ENTERPRISE_FQDN"
  echo "  CONTEXT:                   $CONTEXT"
  echo "  ORGANIZATION URL:          $SITE_URL/$CONTEXT"
  echo ""

  echo_v "  COMMAND=$(get_configure_curl_cmd)"
  echo_v ""

  if [ "$SILENT" = false ]; then
    echo -n "Create organization using these properties ([y]/n)? "
    read ans

    [ -z "$ans" ] && ans="y"

    [ "$ans" != "y" ] && exit_msg "Exiting."
 fi
}

process_args()
{
  while getopts "hf:u:svd?" opt
  do
    case "$opt" in
      h)
        banner
        usage
        ;;
      f)
        CONFIGURE_PROPERTIES=${OPTARG}
        ;;
      u)
        USER_MANAGED_DATASTORES=${OPTARG}
        ;;
      s)
        SILENT=true
        ;;
      v)
        VERBOSE=true
        ;;
      d)
        DEBUG=true
        ;;
      *)
        echo "-- What? --"
        usage
        ;;
    esac
  done

  if [ -z "$CONFIGURE_PROPERTIES" ]; then
    banner
    usage
  fi
}

Main()
{
  init_temp_dir
  sanity_check

  . "${COMMON}"

  process_args "$@"

  validation_check

  if ! is_admin_pod_running ; then
    info_exit "${PRODUCT_NAME} is not running. Run the 'deploy.sh' script before running this script."
  fi

  check_admin_url

  if is_site_configured ; then
    info_exit "An organization is already defined. You will need to undeploy and redeploy to recreate the organization."
  fi

  validate_portal_license

  if is_configure_in_progress ; then
    poll_site_status
  else
    create_storage_json
    echo ""
    get_version_tag
    banner
    prompt_user
    create_site
    poll_site_status
  fi

  local res=$(get_site_status)
  local state=$(echo $res | awk -F "|" '{print $1}')
  local message=$(echo $res | awk -F "|" '{print $2}')

  if [ "$state" = "failed" ]; then
    fail "$message"
  else
    show_success "$message"
  fi

  echo ""
  cleanup
}

Main "$@"
