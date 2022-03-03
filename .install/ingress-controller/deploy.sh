#!/bin/bash

PROG=$(basename "$0")
CWD="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="ingress-controller"
PROPERTIES="${CWD}/${BASE_NAME}.properties"
RESOURCES="$(cd "${CWD}/../resources" && pwd)"
COMMON="${RESOURCES}/scripts/common.sh"
CUSTOM_PROPERTIES=""
YAML_TEMP="${RESOURCES}/tmp/${BASE_NAME}.yaml.$$.tmp"
ADMIN_PROPERTIES="${CWD}/../arcgis-enterprise/arcgis-enterprise.properties"
INGRESS_TLS_SECRET_NAME="changeit"
TEMP_KEY_FILE="${RESOURCES}/tmp/${BASE_NAME}.keyfile.key.$$.tmp"
TEMP_CRT_FILE="${RESOURCES}/tmp/${BASE_NAME}.certificate.crt.$$.tmp"
TEMP_INTERPOD_PFX_FILE="${RESOURCES}/tmp/${BASE_NAME}.interpod.pfx.$$.tmp"
TLS_CONFIG_FILE="${RESOURCES}/tmp/${BASE_NAME}.tls.conf.$$.tmp"
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
  ingress-controller.yaml
  ingress-controller-service.yaml
)

DEPLOY=true

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

init_temp_dir()
{
  [ "$HELM_DEPLOY" = true ] && {
    YAML_TEMP="/arcgistmp/${BASE_NAME}.yaml.$$.tmp"
    TEMP_KEY_FILE="/arcgistmp/${BASE_NAME}.keyfile.key.$$.tmp"
    TEMP_CRT_FILE="/arcgistmp/${BASE_NAME}.certificate.crt.$$.tmp"
    TEMP_INTERPOD_PFX_FILE="/arcgistmp/${BASE_NAME}.interpod.pfx.$$.tmp"
    TLS_CONFIG_FILE="/arcgistmp/${BASE_NAME}.tls.conf.$$.tmp"
    YAML_COMBINED="/arcgistmp/${BASE_NAME}_combined.yaml"
  }
}

echo_d()
{
  [ "$VERBOSE" = true ] && echo "$1"
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

  [ ! -f "$ADMIN_PROPERTIES" ] && {
    fail "Properties file $ADMIN_PROPERTIES does not exist."
  }
}

check_encryption_keyfile()
{
  [ "$DEPLOY" = false ] && return

  [ "$HELM_DEPLOY" = true ] && return

  [ -z "${ENCRYPTION_KEYFILE}" ] && fail "Variable ENCRYPTION_KEYFILE is not defined."
  [ ! -f "${ENCRYPTION_KEYFILE}" ] && fail "Encryption keyfile not found: ${ENCRYPTION_KEYFILE}"
}

ingress_pod_is_available()
{
  local status=$(kubectl get pods -n ${K8S_NAMESPACE} | grep "${ARCGIS_SITENAME}-ingress-controller")
  [ -n "$status" ]
}

config_map_exists()
{
  local name="$1"
  local status=$(kubectl get configmaps -n ${K8S_NAMESPACE} | grep "$name")
  [ -n "$status" ]
}

tls_secret_exists()
{
  local name="$1"
  local status=$(kubectl get secret -n ${K8S_NAMESPACE} | grep "$name")
  [ -n "$status" ]
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

cleanup()
{
  rm -f "${YAML_COMBINED}"
  rm -f "${YAML_TEMP}"
  rm -f "${TEMP_KEY_FILE}"
  rm -f "${TEMP_CRT_FILE}"
  rm -f "${TEMP_INTERPOD_PFX_FILE}"
  rm -f "${TLS_CONFIG_FILE}"
}

uncomment_yaml_section()
{
  local sed_cmd="sed -i"
  local sed_string=""
  local yaml_section="$1"

  [ "$(uname -s)" = "Darwin" ] && sed_cmd="sed -i ''"

  sed_string="s%^[[:space:]]*#${yaml_section}%    ${yaml_section}%g"

  # Run sed.  NOTE: do not use eval.  It messes up the sed string
  ${sed_cmd} "${sed_string}" "${YAML_TEMP}"

  [ $? -ne 0 ] && fail "Failed to parse AWS NLB options in yaml."
}

enable_load_balancer_options()
{
  case "$LOAD_BALANCER_TYPE" in
    azure-external|gcp-external)
      return    # not used
      ;;
    azure-internal)
      uncomment_yaml_section "service.beta.kubernetes.io/azure-load-balancer-internal"
      ;;
    aws-nlb-external)
      uncomment_yaml_section "service.beta.kubernetes.io/aws-load-balancer-backend-protocol"
      uncomment_yaml_section "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled"
      uncomment_yaml_section "service.beta.kubernetes.io/aws-load-balancer-scheme"
      ;;
    aws-nlb-internal)
      uncomment_yaml_section "service.beta.kubernetes.io/aws-load-balancer-scheme"
      ;;
    gcp-internal)
     uncomment_yaml_section "networking.gke.io/load-balancer-type"
     ;;
  esac
}

handle_openshift_route()
{
  [ -z "${USE_OPENSHIFT_ROUTE}" ] || [ "${USE_OPENSHIFT_ROUTE}" = false ] && return

  local sed_cmd="sed -i"

  [ "$(uname -s)" = "Darwin" ] && sed_cmd="sed -i ''"

  # WARNING: These sed commands will delete all occurences of these lines from the combined yaml.
  # If new type: or nodePort: lines are added they will be deleted if USE_OPENSHIFT_ROUTE=true.

  # Delete the nodePort: XXXXX line from service yaml
  ${sed_cmd} '/nodePort:/d' "${YAML_TEMP}"
  [ $? -ne 0 ] && fail "Failed to delete 'nodePort: XXXXX' line from yaml"

  # Delete spec -> type: nodePort line from service yaml
  ${sed_cmd} '/  type:/d' "${YAML_TEMP}"
  [ $? -ne 0 ] && fail "Failed to delete 'type: nodePort' line from yaml"
}

generate_tls_config_file()
{
cat << EOF > "${TLS_CONFIG_FILE}"
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
O = ArcGISEnterprise
CN = ${INGRESS_SERVER_TLS_SELF_SIGN_CN}
[v3_req]
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${INGRESS_SERVER_TLS_SELF_SIGN_CN}
EOF
  [ $? -ne 0 ] && fail "Failed to generate tls config file ${TLS_CONFIG_FILE}."
}

generate_yaml()
{
  echo_d ""
  echo_d "Using input properties:"

  echo_d "  PROPERTIES = $ADMIN_PROPERTIES"
  echo_d "  DEPLOY = $DEPLOY"

  cp -p "$YAML_COMBINED" "$YAML_TEMP"

  while IFS= read line
  do
    var=$(echo "$line" | cut -d= -f1)
    val=${!var}

    grep -q -w "${var}" "${YAML_COMBINED}"
    if [ $? -eq 0 ]; then
      if [ "$(uname -s)" = "Darwin" ]; then
        sed -i '' 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
      else
        sed -i 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
      fi

      echo_d "  ${var} = ${val}"
    fi

  done < <(cat "$ADMIN_PROPERTIES" | grep -Ev "^#|^$")
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

  [ $res -eq 0 ]
}

run_cmd()
{
  local cmd="$1"
  local msg="$2"

  [ -z "$msg" ] && msg="Run $cmd"

  eval $cmd

  [ $? -ne 0 ] && fail "Command failed: $msg"

  true
}

generate_tls_certificate_secret() {
  # We create a self-signed tls cert and secret for interpod communication
  if [ "$DEPLOY" = true ] ; then
    run_cmd "openssl req -x509 -newkey rsa:2048 -nodes -keyout \"${TEMP_KEY_FILE}\" -out \"${TEMP_CRT_FILE}\" -sha256 -days 3650 -subj \"/CN=*.${K8S_NAMESPACE}.${K8S_SERVICE_DNS_SUFFIX}\""

    # create kubernetes '[siteName]-interpod-cert-pem' secret with pem files
    run_cmd "kubectl create secret tls ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PEM_SUFFIX} \
      --cert=\"${TEMP_CRT_FILE}\" --key=\"${TEMP_KEY_FILE}\" -n ${K8S_NAMESPACE}"

    # label secret for siteName
    run_cmd "kubectl label secret ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PEM_SUFFIX} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"

     # label secret for tier
    run_cmd "kubectl label secret ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PEM_SUFFIX} -n ${K8S_NAMESPACE} arcgis/tier=config"

    # create the pfx file (tomcat only works with pfx or jks, it does not work with crt/key file)
    run_cmd "openssl pkcs12 -export -out \"${TEMP_INTERPOD_PFX_FILE}\" -inkey \"${TEMP_KEY_FILE}\" -in \"${TEMP_CRT_FILE}\" -password pass:changeit"

    # create kubernetes '[siteName]-interpod-cert-pfx' secret, this will be later loaded into tomcat servers
    run_cmd "kubectl create secret generic ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PFX_SUFFIX} \
      --from-file=default-pfx=\"${TEMP_INTERPOD_PFX_FILE}\" -n ${K8S_NAMESPACE}"

    # label secret for siteName
    run_cmd "kubectl label secret ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PFX_SUFFIX} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"

    # label secret for tier
    run_cmd "kubectl label secret ${ARCGIS_SITENAME}-${DEFAULT_INTERPOD_CERT_PFX_SUFFIX} -n ${K8S_NAMESPACE} arcgis/tier=config"

  fi

  # Process for Option 1: TLS Certificate secret name provided
  if [ "$DEPLOY" = true ] && [ -n "$INGRESS_SERVER_TLS_SECRET" ] ; then

    # Check that the secret exists before doing anything
    if ! tls_secret_exists "$INGRESS_SERVER_TLS_SECRET" ; then
      fail "The secret \"${INGRESS_SERVER_TLS_SECRET}\" does not exist in the ${K8S_NAMESPACE} namespace."
    fi

    # update the current default
    export INGRESS_TLS_SECRET_NAME="${INGRESS_SERVER_TLS_SECRET}"

  # Process for Option 2: PFX file inputs
  elif [ "$DEPLOY" = true ] && [ -n "$INGRESS_SERVER_TLS_PFX_FILE" ] && [ -n "$INGRESS_SERVER_TLS_PFX_PSSWD" ]; then

    local decode_flag="-d"
    local pfx_password="$INGRESS_SERVER_TLS_PFX_PSSWD"

    [ "$(uname -s)" = "Darwin" ] && decode_flag="-D"

    if [ "$HELM_DEPLOY" = false ]; then
      # Decrypt pw if necessary
      if ! $(can_decrypt_aes256_string "$pfx_password" "${ENCRYPTION_KEYFILE}") ; then
        fail "Failed to decrypt pfx password."
      fi
      pfx_password=$(get_decrypted_aes256_string "$pfx_password" "${ENCRYPTION_KEYFILE}")
    fi

    # Escape special shell chars
    pfx_password=$(printf "%q" "$pfx_password")

    # Get the key file from pfx, and store it in temp file.
    run_cmd "openssl pkcs12 -in \"${INGRESS_SERVER_TLS_PFX_FILE}\" -nocerts -out \"${TEMP_KEY_FILE}\" -nodes -password pass:${pfx_password}"

    # Get the key file from pfx, and store it in temp file.
    run_cmd "openssl pkcs12 -in \"${INGRESS_SERVER_TLS_PFX_FILE}\" -nokeys -out \"${TEMP_CRT_FILE}\" -password pass:${pfx_password}"

    # Generate the tls K8s secret using the key and crt
    run_cmd "kubectl -n ${K8S_NAMESPACE} create secret tls ${DEFAULT_INGRESS_SERVER_TLS_SECRET} --cert=\"${TEMP_CRT_FILE}\" --key=\"${TEMP_KEY_FILE}\""

    # label secret for siteName
    run_cmd "kubectl label secret ${DEFAULT_INGRESS_SERVER_TLS_SECRET} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"

    # update the current default
    export INGRESS_TLS_SECRET_NAME="${DEFAULT_INGRESS_SERVER_TLS_SECRET}"

  # Process for Option 3: KEY and CRT inputs.
  elif [ "$DEPLOY" = true ] && [ -n "$INGRESS_SERVER_TLS_KEY_FILE" ] && [ -n "$INGRESS_SERVER_TLS_CRT_FILE" ]; then

    # Generate the tls K8s secret using the key and crt
    run_cmd "kubectl -n ${K8S_NAMESPACE} create secret tls ${DEFAULT_INGRESS_SERVER_TLS_SECRET} --cert=\"${INGRESS_SERVER_TLS_CRT_FILE}\" --key=\"${INGRESS_SERVER_TLS_KEY_FILE}\""

    # label secret for siteName
    run_cmd "kubectl label secret ${DEFAULT_INGRESS_SERVER_TLS_SECRET} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"

    # update the current default
    export INGRESS_TLS_SECRET_NAME="${DEFAULT_INGRESS_SERVER_TLS_SECRET}"

  # Process for Option 4: Self sign, Generate KeyPair
  elif [ "$DEPLOY" = true ] && [ -n "$INGRESS_SERVER_TLS_SELF_SIGN_CN" ]; then

    # Generate a key-pair based on CN name
    generate_tls_config_file
    run_cmd "openssl req -x509 -newkey rsa:2048 -keyout \"${TEMP_KEY_FILE}\" -out \"${TEMP_CRT_FILE}\" -days 365 -sha256 -config \"${TLS_CONFIG_FILE}\" -nodes"

    # Generate the tls K8s secret using the key and crt
    run_cmd "kubectl -n ${K8S_NAMESPACE} create secret tls ${DEFAULT_INGRESS_SERVER_TLS_SECRET} --cert=\"${TEMP_CRT_FILE}\" --key=\"${TEMP_KEY_FILE}\""

    # label secret for siteName
    run_cmd "kubectl label secret ${DEFAULT_INGRESS_SERVER_TLS_SECRET} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"

    # update the current default
    export INGRESS_TLS_SECRET_NAME="${DEFAULT_INGRESS_SERVER_TLS_SECRET}"

  fi
}

delete_tls_certificate_secret() {
  # Any option other than Option 1, delete the secret, as it was created by deploy script.
  if [ "$DEPLOY" = false ] && [ -z "$INGRESS_SERVER_TLS_SECRET" ];  then
    # Delete the tls K8s secret
    CMD="kubectl -n ${K8S_NAMESPACE} delete secret ${DEFAULT_INGRESS_SERVER_TLS_SECRET} --ignore-not-found"
    eval $CMD
    res=$?

    [ $res -ne 0 ] && fail "Command failed: $CMD"

    [ $res -eq 0 ]

  fi
}

# wait_for_config_map_exists()
# {
#   local timeout=$1
#   local timedout=false
#   local START=$SECONDS
#   local config_map="${ING_CNTRLR_ELECTION_ID}-${INGRESS_CLASS}"
#
#   while :
#   do
#     echo "Waiting for config map: $config_map"
#     if config_map_exists "$config_map" ; then
#       break
#     fi
#
#   sleep 1
#
#   local ELAPSED=$(($SECONDS - $START))
#   if [ $ELAPSED -gt $timeout ]; then
#     timedout=true
#     break
#   fi
#
#   done
#
#   [ "$timedout" = false ]
# }

# label_leader_config_map()
# {
#   if [ "$DEPLOY" = true ]; then
#     if wait_for_config_map_exists 120 ; then
#       run_cmd "kubectl label configmap ${ING_CNTRLR_ELECTION_ID}-${INGRESS_CLASS} -n ${K8S_NAMESPACE} arcgis/siteName=${ARCGIS_SITENAME}"
#       run_cmd "kubectl label configmap ${ING_CNTRLR_ELECTION_ID}-${INGRESS_CLASS} -n ${K8S_NAMESPACE} arcgis/app=ingress-nginx"
#     else
#       printf "\nWARNING: Timed out waiting for config map: ${ING_CNTRLR_ELECTION_ID}-${INGRESS_CLASS}\n\n"
#     fi
#   fi
# }

Main()
{
  check_args "$@"

  . "$ADMIN_PROPERTIES"

  [ -f "$CUSTOM_PROPERTIES" ] && {
    echo_d "Sourcing custom properties file: $CUSTOM_PROPERTIES"
    . "$CUSTOM_PROPERTIES"

    # Re-source the default properties files so variables using any new values are re-evaluated
    . "$ADMIN_PROPERTIES"

     # Re-source custom properties again so those values are re-evaluated
    . "$CUSTOM_PROPERTIES"
  }

  [ ! -f "$COMMON" ] && fail "Common script not found: $COMMON"
  . "$COMMON"

  # do this first
  init_temp_dir
  check_encryption_keyfile
  combine_yaml_files
  # runs only for deploy
  generate_tls_certificate_secret
  generate_yaml
  enable_load_balancer_options
  handle_openshift_route
  apply_yaml
  # runs only for undeploy
  delete_tls_certificate_secret
  # label_leader_config_map # not needed
  cleanup
}


Main "$@"
