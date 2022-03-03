#!/bin/bash

PROG=$(basename "$0")
CWD="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="arcgis-enterprise"
PROPERTIES="${CWD}/${BASE_NAME}.properties"
CUSTOM_PROPERTIES=""
RESOURCES="$(cd "${CWD}/../resources" && pwd)"
COMMON="${RESOURCES}/scripts/common.sh"
YAML_TEMP="${RESOURCES}/tmp/${BASE_NAME}.yaml.$$.tmp"
DEPLOY=true
AGS_ENV="${CWD}/ags-env.dat"
YAML_COMBINED="${RESOURCES}/tmp/${BASE_NAME}_combined.yaml"
OS=$(uname -s)
VERBOSE=${VERBOSE:-false}

# Set PATH and LD_LIBRARY_PATH to use any local binaries
if [ -f "${RESOURCES}/ssl/${OS}/openssl.cnf" ]; then
  export PATH=${RESOURCES}/bin/${OS}:${PATH}
  export LD_LIBRARY_PATH=${RESOURCES}/lib/${OS}:${LD_LIBRARY_PATH}
  export OPENSSL_CONF=${RESOURCES}/ssl/${OS}/openssl.cnf
fi

YAML_LIST=(
  base-config.yaml
  arcgis-enterprise.yaml
)

BASE64_ENCODE_VARS=(
  CONTAINER_REGISTRY_PASSWORD
  INGRESS_SERVER_TLS_PFX_PSSWD
)

usage()
{
  echo "Usage: ${PROG} [-u] [input.properties]"
  echo ""
  echo "  -u                  - Undeploy"
  echo "  my.input.properties - Alternate input properties file"
  echo ""
  echo "The default input properties file is $(basename ${PROPERTIES})."
  echo ""
  echo "Examples:"
  echo ""
  echo "  ./${PROG}                    - Deploy using the default properties file"
  echo "  ./${PROG} -u                 - Uneploy using the default properties file"
  echo "  ./${PROG} my.properties      - Deploy using the alternate properties file"
  echo "  ./${PROG} -u my.properties   - Uneploy using the alternate properties file"
  echo ""
  exit 0
}

fail()
{
  echo ""
  echo "ERROR: $1"
  echo ""
  exit 1
}

echo_d()
{
  [ "$VERBOSE" = true ] && echo "$1"
}

init_temp_dir()
{
  [ "$HELM_DEPLOY" = true ] && {
    YAML_TEMP="/arcgistmp/${BASE_NAME}.yaml.$$.tmp"
    YAML_COMBINED="/arcgistmp/${BASE_NAME}_combined.yaml"
    AGS_ENV="/arcgistmp/ags-env.dat"
  }
}

cleanup()
{
  rm -f "${YAML_TEMP}"
  rm -f "${YAML_COMBINED}"
}

check_args()
{
  while getopts "hu" opt
  do
    case "$opt" in
      h) usage
         ;;
      u) DEPLOY=false
         shift
         ;;
    esac
  done

  [ -n "$1" ] && {
    CUSTOM_PROPERTIES="$1"
  }

  [ ! -f "$PROPERTIES" ] && {
    fail "Properties file $PROPERTIES does not exist."
  }
}

combine_yaml_files()
{
  rm -f "$YAML_COMBINED"

  for yaml in "${YAML_LIST[@]}"
  do
    local local_yaml="${CWD}/${yaml}"
    [ ! -f "$local_yaml" ] && fail "Could not find local yaml file: $local_yaml"
    cat "$local_yaml" >> "$YAML_COMBINED"
    echo -e "\n---\n" >> "$YAML_COMBINED"
  done
}

generate_sha256sum()
{
  local sha=$(openssl sha256 "$@")
  # Strip off (stdin)= if present
  echo -n ${sha#*= }
}

generate_elastic_credentials()
{
  local user=""
  local pass=""
  local sufx=""

  if [ "$(uname -s)" = "Darwin" ]; then
    user=$(date +%s | generate_sha256sum | head -c 24 | base64)
    sleep 1.2
    pass=$(date +%s | generate_sha256sum | head -c 32 | base64)
    sleep 1.2
    sufx=$(date +%s | generate_sha256sum | head -c 4)
  else
    user=$(date +%s%N | generate_sha256sum | head -c 24 | base64)
    pass=$(date +%s%N | generate_sha256sum | head -c 32 | base64)
    sufx=$(date +%s%N | generate_sha256sum | head -c 4)  
  fi

  ELASTICSEARCH_USERNAME="$user"
  ELASTICSEARCH_PASSWORD="$pass"
  ELASTICSEARCH_SERVICE_NAME="${ARCGIS_SITENAME}-spatiotemporal-index-store-${sufx}"
}

can_convert_to_base64()
{
  local var="$1"
  local res=""

  res=$(echo "${BASE64_ENCODE_VARS[@]}" | grep -w "$var")
  [ -n "$res" ]
}

convert_to_base64()
{
  local var="$1"
  local val="$2"

  [ -z "$val" ] && return

  local text_pw=""
  local base64_pw=""

  if [ "$HELM_DEPLOY" = true ]; then
    text_pw="$val"
  else
    text_pw=$(get_decrypted_aes256_string "$val" "$ENCRYPTION_KEYFILE")
  fi
  base64_pw=$(encode_base64 "$text_pw")

  echo "$base64_pw"
}

create_ags_env_cfg_map()
{
  kubectl create configmap ${K8S_NAME_ENV_VARIABLES_SECRET} --namespace=${K8S_NAMESPACE} --from-file="${AGS_ENV}"
  [ $? -ne 0 ] && fail "Failed to create ${K8S_NAME_ENV_VARIABLES_SECRET} configmap."
}

create_ags_env_json_vars()
{
  local env_variables="{"

  while IFS= read line
  do
    local var=$(echo "$line" | cut -d= -f1)
    local val=$(echo "$line" | cut -d= -f2- | sed 's^\"^^g')

    if $(can_convert_to_base64 "$var") ; then
      val=$(convert_to_base64 "$var" "$val")
    fi

    # append to json list
    env_variables=$env_variables"\"${var}\":\"${val}\","

  done < <(cat "$AGS_ENV")

  # Remove last comma and add closing brace
  env_variables="${env_variables%?}}"

  if [ "$(uname -s)" = "Darwin" ]; then
    sed -i '' 's^${ENV_VARIABLES}^'"${env_variables}"'^g' "${YAML_TEMP}"
  else
    sed -i 's^${ENV_VARIABLES}^'"${env_variables}"'^g' "${YAML_TEMP}"
  fi
}

generate_yaml()
{
  local tmp_file="/tmp/ags_temp.$$.tmp"
  echo_d ""
  echo_d "Using input properties:"

  echo_d "  PROPERTIES = $PROPERTIES"
  echo_d "  DEPLOY = $DEPLOY"

  rm -f "${AGS_ENV}"

  cp -p "$YAML_COMBINED" "$YAML_TEMP"

  generate_elastic_credentials

  while IFS= read line
  do
    var=$(echo "$line" | cut -d= -f1)
    val=${!var}

    if [ "$(uname -s)" = "Darwin" ]; then
      sed -i '' 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
    else
      sed -i 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
    fi

    echo_d "  ${var} = ${val}"
    echo "${var}=\"${val}\"" >> "${tmp_file}"

  done < <(cat "$PROPERTIES" | grep -Ev "^#|^$")

  cat "$tmp_file" | sort > "$AGS_ENV"
  rm -f "$tmp_file"

  [ "$DEPLOY" = true ] && create_ags_env_json_vars
}

apply_yaml()
{
  local apply_cmd="apply"
  local apply_opt=""

  [ "$DEPLOY" = false ] && {
    apply_cmd="delete"
    apply_opt="--ignore-not-found"
  }

  CMD="kubectl ${apply_cmd} ${apply_opt} -f \"$YAML_TEMP\""
  eval $CMD
  res=$?

  [ $res -ne 0 ] && fail "Command failed: $CMD"

  rm -f "$YAML_TEMP"
  rm -f "$AGS_ENV"

  [ $res -eq 0 ]
}

Main()
{
  check_args "$@"
  . "$PROPERTIES"

  [ -f "$CUSTOM_PROPERTIES" ] && {
    echo_d "Sourcing custom properties file: $CUSTOM_PROPERTIES"
    . "$CUSTOM_PROPERTIES"

    # Re-source the default properties files so variables using any new values are re-evaluated
    . "$PROPERTIES"

    # Re-source custom properties again so those values are re-evaluated
    . "$CUSTOM_PROPERTIES"
  }

  [ ! -f "$COMMON" ] && fail "Common script not found: $COMMON"
  . "$COMMON"

  # do this first
  init_temp_dir
  combine_yaml_files
  generate_yaml
  #create_ags_env_cfg_map
  apply_yaml
  cleanup
}


Main "$@"

