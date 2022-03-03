#!/bin/bash

PROG=$(basename "$0")
PROG_BASE=${PROG%%.*}
CWD="$(cd "$(dirname "$0")" && pwd)"
OS=$(uname -s)
COMMON="${CWD}/common.sh"
. "$COMMON"

COLS=0
ROWS=0

SCRIPTS_DIR="$(cd "${CWD}/../../../" && pwd)"
RESOURCES="${SCRIPTS_DIR}/.install/resources"
PROPERTIES_FILE_DEFAULT="${RESOURCES}/templates/custom.properties.default"
PROPERTIES_FILE_INTERNAL="${RESOURCES}/templates/custom.properties.internal"
PROPERTIES_FILE=""
DEPLOY_INTERNAL=true
DEPLOY_SCRIPT="${SCRIPTS_DIR}/deploy.sh"
UNDEPLOY_SCRIPT="${SCRIPTS_DIR}/undeploy.sh"

# Set PATH and LD_LIBRARY_PATH to use any local binaries
if [ -f "${RESOURCES}/ssl/${OS}/openssl.cnf" ]; then
  export PATH=${RESOURCES}/bin/${OS}:${PATH}
  export LD_LIBRARY_PATH=${RESOURCES}/lib/${OS}:${LD_LIBRARY_PATH}
  export OPENSSL_CONF=${RESOURCES}/ssl/${OS}/openssl.cnf
fi

# Tag will be passed back to the deploy script
VERSION_TAG=""

if [ ! -f "${PROPERTIES_FILE_INTERNAL}" ]; then
  . "${PROPERTIES_FILE_DEFAULT}"
  DEPLOY_INTERNAL=false
else
  . "${PROPERTIES_FILE_INTERNAL}"
fi

# Handle signals
trap ctrlc_handler INT
trap cleanup HUP QUIT TERM KILL


# ------------------------------------------------------------------
# UI
# ------------------------------------------------------------------
show_result()
{
  printf "%4s%s " '' "$1"

  draw_ellipses $(( 66 - ${#1} ))
  success
}

intro()
{
cat << EOF

${PRODUCT_NAME} requires several pieces of information before
deploying on your Kubernetes cluster. You should only have to supply this
information once. A properties file will be created to save the values
you entered for future deployments.

Please answer the following questions to configure your cluster. Press Enter
to accept the defaults, which are given in brackets.
EOF
}

ctrlc_handler()
{
  echo ""
  echo ""
  warning "You need to complete the configuration steps at least once in order to deploy."
  cleanup
}

cleanup()
{
  local code=$1
  echo ""
  [ -z "$code" ] && exit 1 || exit $code
}


deploy_enterprise_admin()
{
  TAG_OPT=""

  [ -n "$VERSION_TAG" ] && TAG_OPT="-t $VERSION_TAG"

  if [ -f "$PROPERTIES_FILE" ]; then
    "${DEPLOY_SCRIPT}" -f "${PROPERTIES_FILE}" ${TAG_OPT}
    cleanup 0
  fi
}

# ------------------------------------------------------------------
# Properties file
# ------------------------------------------------------------------
save_properties_file()
{
  if [ "$DEPLOY_INTERNAL" = false ]; then
    cp -p "${PROPERTIES_FILE_DEFAULT}" "${PROPERTIES_FILE}"
  else
    cp -p "${PROPERTIES_FILE_INTERNAL}" "${PROPERTIES_FILE}"
  fi

  section_header "SUMMARY"

  echo ""

  set_properties_var "K8S_NAMESPACE" "$K8S_NAMESPACE"

  set_properties_var "ENCRYPTION_KEYFILE" "$ENCRYPTION_KEYFILE"
  set_properties_var "REGISTRY_HOST" "$REGISTRY_HOST"
  set_properties_var_default "REGISTRY_REPO" "$REGISTRY_REPO"
  set_properties_var "CONTAINER_REGISTRY_USERNAME" "$CONTAINER_REGISTRY_USERNAME"
  set_properties_var "CONTAINER_REGISTRY_PASSWORD" "$CONTAINER_REGISTRY_PASSWORD"

  set_properties_var "ARCGIS_ENTERPRISE_FQDN" "$ARCGIS_ENTERPRISE_FQDN"
  set_properties_var "CONTEXT" "$CONTEXT"
  set_properties_var "NODE_PORT_HTTPS" "$NODE_PORT_HTTPS"
  set_properties_var "INGRESS_TYPE" "$INGRESS_TYPE"

  set_properties_var "INGRESS_SERVER_TLS_SECRET" "$INGRESS_SERVER_TLS_SECRET"

  set_properties_var "INGRESS_SERVER_TLS_PFX_FILE" "$INGRESS_SERVER_TLS_PFX_FILE"
  set_properties_var "INGRESS_SERVER_TLS_PFX_PSSWD" "$INGRESS_SERVER_TLS_PFX_PSSWD"

  set_properties_var "INGRESS_SERVER_TLS_KEY_FILE" "$INGRESS_SERVER_TLS_KEY_FILE"
  set_properties_var "INGRESS_SERVER_TLS_CRT_FILE" "$INGRESS_SERVER_TLS_CRT_FILE"

  set_properties_var "INGRESS_SERVER_TLS_SELF_SIGN_CN" "$INGRESS_SERVER_TLS_SELF_SIGN_CN"

  set_properties_var "LOAD_BALANCER_TYPE" "$LOAD_BALANCER_TYPE"
  set_properties_var "LOAD_BALANCER_IP" "$LOAD_BALANCER_IP"
  set_properties_var "USE_OPENSHIFT_ROUTE" "$USE_OPENSHIFT_ROUTE"

  echo ""
  draw_line
  echo "Properties file saved:"
  echo ""
  echo "    ${PROPERTIES_FILE}"
  echo ""
  echo "Use this filename as an argument when deploying and undeploying:"
  echo ""
  echo "    % ./$(basename "${DEPLOY_SCRIPT}") -f $(basename "${PROPERTIES_FILE}")"
  echo ""
  echo "    % ./$(basename "${UNDEPLOY_SCRIPT}") -f $(basename "${PROPERTIES_FILE}")"
  echo ""
  draw_line

  echo ""
  echo -n "Press any key to deploy, 'q' to quit: "
  read -s -n 1 key

  printf "\r%-79s\r" " "

  [ "$key" = "q" ] && cleanup 0
}

# Create a VARTIABLE="value" property
set_properties_var()
{
  local var="$1"
  local val="$2"

  printf "    %-38s = %s\n" "$(echo $var | sed 's/_/ /g'):" "$val"

  if [ "$val" = "true" ] || [ "$val" = "false" ]; then
    edit_in_file "s|^\(${var}\s*=\s*\).*\$|\1${val}|" "${PROPERTIES_FILE}"
  else
    edit_in_file "s|^\(${var}\s*=\s*\).*\$|\1\"${val}\"|" "${PROPERTIES_FILE}"
  fi
}

# Create a VARIABLE="${VARIABLE:-default-value}" property
set_properties_var_default()
{
  local var="$1"
  local val="$2"

  printf "    %-38s = %s\n" "$(echo $var | sed 's/_/ /g'):" "$val"

  edit_in_file "s|^\(${var}\s*=\s*\).*\$|\1\"\${${var}:-${val}}\"|" "${PROPERTIES_FILE}"
}


# ==============================================================================================================

# ------------------------------------------------------------------
# Load Balancer (AWS, EKS and Azure)
# ------------------------------------------------------------------
validate_load_balancer_type()
{
  local err=0

  if [ "$1" != "1" ] && 
     [ "$1" != "2" ] && 
     [ "$1" != "3" ] && 
     [ "$1" != "4" ] && 
     [ "$1" != "5" ] && 
     [ "$1" != "6" ]; then
    error_msg "Enter the number 1, 2, 3, 4, 5 or 6"
    err=1
  fi

  [ $err -eq 0 ]
}

validate_ip()
{
  local err=0
  local ip="$1"

  is_valid_ip "$ip" || {
    error_msg "Enter an IP address in the form XXX.XXX.XXX.XXX."
    err=1
  }
  [ $err -eq 0 ]
}

configure_load_balancer()
{
  local load_balancer_type="azure-external"

  section_header "LOAD BALANCER"

  export INGRESS_TYPE="LoadBalancer"

  section_description "${PRODUCT_NAME} can provision selected cloud load balancers."

  # Load Balancer Type
  section_prompt "Select one of the following options to indicate the type of load balancer you want to provision:"
  echo "        1 - Azure Load Balancer (External)"
  echo "        2 - Azure Load Balancer (Internal)"
  echo "        3 - AWS Network Load Balancer (External)"
  echo "        4 - AWS Network Load Balancer (Internal)"
  echo "        5 - Google Cloud Platform TCP Load Balancer (External)"
  echo "        6 - Google Cloud Platform TCP Load Balancer (Internal)"
  echo ""

  while :
  do
    printf "    Enter load balancer type 1-6 : "
    read ans

    validate_load_balancer_type "$ans"
    [ $? -eq 0 ] && break
  done

  case "$ans" in
    1) load_balancer_type="azure-external"
      ;;
    2) load_balancer_type="azure-internal"
      ;;
    3) load_balancer_type="aws-nlb-external"
      ;;
    4) load_balancer_type="aws-nlb-internal"
      ;;    
    5) load_balancer_type="gcp-external"
      ;;
    6) load_balancer_type="gcp-internal"
      ;;    
  esac

  export LOAD_BALANCER_TYPE="$load_balancer_type"

  echo ""

  # Load Balancer IP
  local load_balancer_ip=""

  section_prompt "Some cloud providers allow you to specify the load balancer's IP address. In those cases, the load balancer is created with the IP you have specified. Enter the pre-provisioned IP address if you have one, or press Enter if you want the cloud provider to assign one."

  while :
  do
    prompt "Load Balancer IP (or blank for none)"
    read load_balancer_ip

    [ -z "$load_balancer_ip" ] && break

    validate_ip "$load_balancer_ip"
    [ $? -eq 0 ] && break
  done

  export LOAD_BALANCER_IP="$load_balancer_ip"

}

# ------------------------------------------------------------------
# Deployment Platform
# ------------------------------------------------------------------
validate_platform_choice()
{
  local err=0

  if [ "$1" != "1" ] && [ "$1" != "2" ]; then
    error_msg "Enter 1 or 2"
    err=1
  fi

  [ $err -eq 0 ]
}

configure_openshift_route()
{
  echo ""

  while :
  do
    prompt "For Red Hat OpenShift, will you use an OpenShift Route for incoming traffic (y/[n]) ?"
    read ans
    [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "n" ] && break
  done
  
  if [ "$ans" = "y" ]; then
    export USE_OPENSHIFT_ROUTE=true
  fi
}

configure_deployment_platform()
{
  section_header "DEPLOYMENT PLATFORM"

  section_description "${PRODUCT_NAME} uses Ingress to route incoming traffic to the services in the cluster. If you are deploying in a managed Kubernetes service by a cloud provider, such as Amazon Web Services EKS or Microsoft Azure AKS, the ingress controller can be exposed externally using a Load Balancer Service by the cloud provider. In this case, ArcGIS Enterprise on Kubernetes will provision a load balancer during the deployment process."

  echo ""

  while :
  do
    prompt "Do you want to provision a cloud load balancer (y/[n]) ?"
    read ans
    [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "n" ] && break
  done

  if [ -n "$ans" ] && [ "$ans" = "y" ]; then
    configure_load_balancer
  else
    export INGRESS_TYPE="NodePort"
    export LOAD_BALANCER_TYPE=""
    configure_openshift_route
  fi
}

# ------------------------------------------------------------------
# Namespace
# ------------------------------------------------------------------
validate_namespace()
{
  local namespace="$1"
  local err=0

  $(has_spaces "$namespace") && {
    error_msg "Namespaces cannot have spaces in them"
    err=1
  }

  kubectl get namespace "$namespace" > /dev/null 2>&1
  [ $? -ne 0 ] && {
    error_msg "Could not validate namespace \"${namespace}\". Please enter a valid namespace."
    err=1
  }

  [ $err -eq 0 ]
}

configure_namespace()
{
  section_header "NAMESPACE"
  section_description "The Kubernetes namespace will be used to deploy ArcGIS Enterprise workloads."

  section_prompt "Enter the namespace to be used by ${PRODUCT_NAME} and its workloads."

  local default_ns=""
  [ "$DEPLOY_INTERNAL" = true ] && default_ns="${K8S_NAMESPACE}"

  while :
  do
    prompt "Namespace" "${default_ns}"
    read ns

    [ -z "$ns" ] && { 
      [ "$DEPLOY_INTERNAL" = true ] && ns=${default_ns} || continue 
    }

    validate_namespace "$ns"
    [ $? -eq 0 ] && break
  done

  echo ""
  export K8S_NAMESPACE="$ns"
}


# ------------------------------------------------------------------
# Encryption keyfile
# ------------------------------------------------------------------
validate_encrytopn_keyfile()
{
  local keyfile="$1"
  local err=0

  if [ ! -f "$keyfile" ]; then
    error_msg "Keyfile not found: $keyfile"
    err=1
  
  elif [ ! -s "$keyfile" ]; then
    error_msg "Keyfile is empty. This file must contain plain text."
    err=1

  elif [ ! -r "$keyfile" ]; then
    error_msg "Keyfile does not have read permissions."
    err=1
    
  fi

  [ $err -eq 0 ]
}

configure_encryption_keyfile()
{
  local  filename=""

  section_header "ENCRYPTION KEYFILE"
  section_description "The encryption keyfile is a plain text file used for AES-256 encryption/decryption of passwords. The contents of this file is arbitrary plain text and SHOULD NOT contain any passwords. This file should remain in a fixed location and the contents should not change."

  section_prompt "Enter the full path of the encryption keyfile."

  while :
  do
    prompt "Keyfile file path" "${ENCRYPTION_KEYFILE}"
    read filename

    [ -z "$filename" ] && continue

    validate_encrytopn_keyfile "$filename"
    [ $? -eq 0 ] && break
  done

  echo ""

  export ENCRYPTION_KEYFILE="$filename"
}


# ------------------------------------------------------------------
# Docker Registry
# ------------------------------------------------------------------
validate_registry_host()
{
  local registry="$1"
  local err=0

  $(str_contains "$registry" "http") && {
    error_msg "Do not use URL syntax. Use the FQDN 'hostname.com' syntax."
    err=1
  }

  $(str_contains "$registry" "/") && {
    error_msg "Do not use paths, just the FQDN."
    err=1
  }

  ! $(is_valid_fqdn "$registry") && {
    error_msg "You need to use a valid FQDN for the registry hostname."
    err=1
  }

  [ $err -eq 0 ]
}

validate_image_path()
{
  local image_path=""
  local err=0

  $(has_spaces "$image_path") && {
    error_msg "The registry value cannot have spaces."
    err=1
  }

  [ $err -eq 0 ]
}

validate_docker_registry()
{
  local registry="$1"
  local user="$2"
  local ass="$3"
  local err=0

  docker --version > /dev/null 2>&1
  [ $? -ne 0 ] && {
    warning_msg "Because Docker is not installed, your access to the container registry could not be verified. The script will proceed."
    return
  }

  docker login --username $user --password $pass $registry > /dev/null 2>&1 
  [ $? -ne 0 ] && {
    error_msg "Registry login to $registry failed."
    err=1
  }

  [ $err -eq 0 ]
}

configure_registry_credentials()
{
  local registry_host=""
  local image_path=""
  local user=""
  local pass=""

  section_header "CONTAINER REGISTRY"
  section_description "The container registry is where ${PRODUCT_NAME} images reside before they are pulled down to your Kubernetes nodes during deployement."

  while :
  do

    section_prompt "Enter the fully qualified domain name of the container registry host."

    # Get registry hostname
    while :
    do
      prompt "Registry host" "${REGISTRY_HOST}"
      read registry

      [ -z "$registry" ] && registry=${REGISTRY_HOST}

      validate_registry_host "$registry"
      [ $? -eq 0 ] && break
    done

    section_prompt "Enter the image repository to pull the container images. For example, on Docker Hub, the repository is the username or organization name"

    # Get registry image path value
    while :
    do
      prompt "Image path" "${REGISTRY_REPO}"
      read image_path

      [ -z "$image_path" ] && image_path=${REGISTRY_REPO}

      validate_image_path "$image_path"
      [ $? -eq 0 ] && break
    done

    section_prompt "Enter the username and password for the container registry."

    # Get username
    while :
    do
      prompt "Registry username" "${CONTAINER_REGISTRY_USERNAME}"
      read user

      if [ "$DEPLOY_INTERNAL" = true ]; then
        [ -z "$user" ] && user=${CONTAINER_REGISTRY_USERNAME}
        break
      else
        [ -n "$user" ] && break
      fi
    done

    # Get password
    while :
    do
      prompt "Registry password"
      read -s pass

      echo ""
      [ -n "$pass" ] && break
    done

    validate_docker_registry "$registry" "$user" "$pass"
    [ $? -eq 0 ] && break

    echo ""
  done

  echo ""

  # Encrypt password
  if ! $(can_encrypt_aes256_string "$pass" "$ENCRYPTION_KEYFILE") ; then
    fail "Unable to encrypt registry password."
  fi

  pass=$(get_encrypted_aes256_string "$pass" "$ENCRYPTION_KEYFILE")
  export REGISTRY_HOST="$registry"
  export REGISTRY_REPO="$image_path"
  export CONTAINER_REGISTRY_USERNAME="$user"
  export CONTAINER_REGISTRY_PASSWORD="$pass"
}


# ------------------------------------------------------------------
# Reverse Proxy
# ------------------------------------------------------------------
validate_hostname()  # Generic hostname check
{
  local host="$1"
  local err=0

  $(str_contains "$host" "http") && {
    error_msg "Do not use URL syntax. Use the FQDN 'hostname.com' syntax."
    err=1
  }

  $(str_contains "$host" "/") && {
    error_msg "Do not use host paths. Use the FQDN 'hostname.com' syntax."
    err=1
  }

  ! $(is_valid_fqdn "$host") && {
    error_msg "You need to enter a valid FQDN."
    err=1
  }

  [ $err -eq 0 ]
}


check_context_chars()
{
  local s="$1"

  if [ -n "$s" ] && [[ "$s" =~ ^[[:alnum:]]*$ ]] || [[ $s == *['.-_~!$&()*+,;=:@']* ]]; then
    return 0
  fi
  return 1
}

validate_site_context()
{
  local context="$1"
  local valid_chars='.-_~!$&()*+,;=:@'
  local err=0

  ! check_context_chars "$context" && {
    error_msg "Enter only these characters (a-zA-Z, 0-9, ${valid_chars})."
    err=1
  }

  [ $err -eq 0 ]
}

validate_node_port()
{
  local port="$1"
  local kind="$2"
  local err=0

  ! $(has_digits_only "$port") && {
    error_msg "The $kind port should contain only digits."
    err=1
  }

  if [ $err -eq 0 ]; then
    if [ $port -lt 30000 ] || [ $port -gt 32767 ]; then
      error_msg "The $kind port ($port) needs to be within the range 30000-32767."
      err=1
    fi
  fi

  [ $err -eq 0 ]
}

configure_reverse_proxy()
{
  local proxy_host=""
  local context=""
  local http_port=""
  local https_port=""

  section_header "FULLY QUALIFIED DOMAIN NAME"
  section_description "A fully qualified domain name (FQDN) is needed to access ArcGIS Enterprise on Kubernetes. This points to a load balancer, reverse proxy, edge router, Web Adaptor or other web front-end point configured to route traffic to the ingress controller. You can create the DNS record after deploying ArcGIS Enterprise on Kubernetes."

  # Proxy hostname
  while :
  do
    section_prompt "Enter the fully qualified domain name to access your ${PRODUCT_NAME}."

    if [ "$DEPLOY_INTERNAL" = true ]; then
      prompt "Fully Qualified Domain Name" "${ARCGIS_ENTERPRISE_FQDN}"
    else
      prompt "Fully Qualified Domain Name"
    fi

    read proxy_host

    if [ -z "$proxy_host" ]; then
      [ "$DEPLOY_INTERNAL" = true ] && proxy_host=${ARCGIS_ENTERPRISE_FQDN} || continue
    fi

    validate_hostname "$proxy_host"
    [ $? -eq 0 ] && break
  done

  # Context

  section_prompt "Enter the context path to be used in the URL for ${PRODUCT_NAME}. For example, the context path of 'https://<FQDN>/arcgis/admin' would be 'arcgis'. The path needs to be single level; more than one level is not supported."

  while :
  do
    prompt "Context Path" "${CONTEXT}"
    read context

    [ -z "$context" ] && context=${CONTEXT}

    validate_site_context "$context"
    [ $? -eq 0 ] && break
  done

  # Node Ports
  local text="The ingress controller is exposed to external traffic over a service type of either “LoadBalancer” or “NodePort”. You can control the port of the NodePort Service for the ingress controller; its value can be in the range of 30000-32767."

  if [ "$DEPLOY_INTERNAL" = false ]; then
    text="${text} You may want to leave this field blank if you want Kubernetes to assign an available port automatically."
  fi
  
  section_prompt "$text"

  while :
  do
    prompt "Port for the ingress controller's NodePort Service" "${NODE_PORT_HTTPS}"
    read https_port
    
    if [ -z "$https_port" ]; then
      [ "$DEPLOY_INTERNAL" = true ] && https_port=${NODE_PORT_HTTPS}
      break
    fi
    
    validate_node_port "$https_port" "HTTPS"
    [ $? -eq 0 ] && break
  done

  # Lower-case the RP host
  proxy_host=$(echo $proxy_host | tr '[A-Z]' '[a-z]')

  echo ""
  export ARCGIS_ENTERPRISE_FQDN="$proxy_host"
  export CONTEXT="$context"
  export NODE_PORT_HTTPS="$https_port"
}


# ------------------------------------------------------------------
# TLS Certificate
# ------------------------------------------------------------------
validate_tls_choice()
{
  local err=0

  if [ "$1" != "1" ] && [ "$1" != "2" ] && [ "$1" != "3" ] && [ "$1" != "4" ]; then
    error_msg "Enter 1, 2, 3 or 4"
    err=1
  fi

  [ $err -eq 0 ]
}

validate_tls_secret()
{
  local secret="$1"
  local err=0

  kubectl get secret $secret -n $K8S_NAMESPACE > /dev/null 2>&1
  [ $? -ne 0 ] && {
    error_msg "Secret \"$secret\" not found."
    err=1
  }
  [ $err -eq 0 ]
}

validate_pfx_file()
{
  local file="$1"
  local err=0

  [ ! -f "$file" ] && {
    error_msg ".PFX file not found: $file"
    err=1
  }
  [ $err -eq 0 ]
}

validate_pfx_password()
{
  local file="$1"
  local pw="$2"
  local err=0

  openssl pkcs12 -in "${file}" -password pass:"${pw}" -info -nokeys > /dev/null 2>&1
  [ $? -ne 0 ] && {
    error_msg "Invalid password for PFX file."
    err=1
  }
  [ $err -eq 0 ]
}

validate_key_file()
{
  local file="$1"
  local err=0

  [ ! -f "$file" ] && {
    error_msg ".KEY file not found: $file"
    err=1
  }
  [ $err -eq 0 ]
}

validate_crt_file()
{
  local file="$1"
  local err=0

  [ ! -f "$file" ] && {
    error_msg ".CRT file not found: $file"
    err=1
  }
  [ $err -eq 0 ]
}

tls_get_secret_name()
{
  local secret=""

  section_prompt "Enter the name of the Kubernetes TLS secret containing the private key and certificate."

  while :
  do
    prompt "Existing TLS secret name"
    read secret

    [ -z "$secret" ] && continue

    validate_tls_secret "$secret"
    [ $? -eq 0 ] && break
  done
  export INGRESS_SERVER_TLS_SECRET="$secret"
}

tls_get_pfx_file()
{
  local pfx_file=""
  local pfx_password=""

  section_prompt "A path to the .pfx file and the pfx file password are required."

  # PFX file
  while :
  do
    prompt "Full path to the .PFX file"
    read pfx_file
    [ -z "$pfx_file" ] && continue

    validate_pfx_file "$pfx_file"
    [ $? -eq 0 ] && break
  done

  # PFX password
  while :
  do
    prompt ".PFX file password"
    read -s pfx_password

    echo ""
    validate_pfx_password "$pfx_file" "$pfx_password"
    [ $? -eq 0 ] && break
  done

  # Encode the PW
  if ! $(can_encrypt_aes256_string "$pfx_password" "$ENCRYPTION_KEYFILE") ; then
    fail "Unable to encrypt pfx password."
  fi

  pfx_password=$(get_encrypted_aes256_string "$pfx_password" "$ENCRYPTION_KEYFILE")

  export INGRESS_SERVER_TLS_PFX_FILE="$pfx_file"
  export INGRESS_SERVER_TLS_PFX_PSSWD="$pfx_password"
}

tls_get_key_crt()
{
  local key_file=""
  local crt_file=""

  section_prompt "Enter the paths to PEM format private Key (.key) and certificate (.crt) files."

  # .KEY file
  while :
  do
    prompt "Full path to the .KEY file"
    read key_file
    [ -z "$key_file" ] && continue

    validate_key_file "$key_file"
    [ $? -eq 0 ] && break
  done

  # .CRT file
  while :
  do
    prompt "Full path to the .CRT file"
    read crt_file
    [ -z "$crt_file" ] && continue

    validate_crt_file "$crt_file"
    [ $? -eq 0 ] && break
  done

  export INGRESS_SERVER_TLS_KEY_FILE="$key_file"
  export INGRESS_SERVER_TLS_CRT_FILE="$crt_file"
}

tls_get_cert_fqdn()
{
  local common_name=""

  section_prompt "A self-signed certificate requires a Common Name."

  while :
  do
    prompt "Common name (CN)"
    read common_name

    # Assume non-null password is correct.  No validation.
    [ -n "$common_name" ] && break
  done

  export INGRESS_SERVER_TLS_SELF_SIGN_CN="$common_name"
}

configure_tls_certificate()
{
  section_header "TLS CERTIFICATE"
  section_description "All communications to ArcGIS Enterprise are encrypted and use Transport Layer Security (TLS). A TLS certificate signed by your Certification Authority (CA) is required for the ingress controller to enable encrypted communication. If you do not have a trusted CA-signed certificate, the deployment process will generate a self-signed certificate for you. Self-signed certificates are not recommended for production environments."
  section_prompt "Choose one of the following options to apply a TLS certificate for Ingress traffic:"

  echo "        1 - Use an existing TLS secret that contains a private key and a certificate"
  echo "        2 - Use a .pfx file that contains the private key and certificate"
  echo "        3 - Use PEM format private Key (.key file) and certificate (.crt file)"
  echo "        4 - Generate a self-signed certificate"
  echo ""

  while :
  do
    printf "    Enter a number 1 through 4: "
    read choice

    validate_tls_choice "$choice"
    [ $? -eq 0 ] && break
  done

  echo ""

  case "$choice" in
    1)
      tls_get_secret_name
      ;;
    2)
      tls_get_pfx_file
      ;;
    3)
      tls_get_key_crt
      ;;
    4)
      tls_get_cert_fqdn
      ;;
  esac

}

# ------------------------------------------------------------------
# Properties File
# ------------------------------------------------------------------
get_cluster_name()
{
  # Use kubectl config to get the current context then use that to get the cluster name
  local kcontext=""
  local kcluster=""
  local cluster_name="k8s"

  kcontext=$(kubectl config current-context) # Could this ever return null?
  kcluster=$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"${kcontext}\")].context.cluster}")

  if [ -n "$kcluster" ]; then
    cluster_name=$(echo "$kcluster" | sed 's^[/ ]^_^g' | cut -d: -f1)
  fi

  echo "$cluster_name"
}

validate_property_file_name()
{
  local filename="$1"
  local err=0

  $(starts_with "$filename" "..") && {
    error_msg "Do not use relative paths.  Enter a filename only or an absolute path."
    err=1
  }
  [ $err -eq 0 ]
}

get_property_file_name()
{
  local filename="arcgis-$(get_cluster_name)-${K8S_NAMESPACE}.properties"

  # Caller passed a filename so use it
  [ -n "$PROPERTIES_FILE" ] && filename="$PROPERTIES_FILE"

  section_header "SAVE A PROPERTIES FILE"

  section_description "A properties file will be saved to allow you to redeploy or undeploy using the settings you just entered. By default, the filename will be arcgis-<cluster>-<namespace>.properties. Here, you can indicate a different filename."
  section_prompt "Enter a name for your properties file, or press Enter to accept the default."

  while :
  do
    prompt "Properties filename" "$filename"
    read name

    [ -z "$name" ] && name="$filename"

    validate_property_file_name "$name"
    [ $? -eq 0 ] && {
      filename="$name"
      break
    }
  done

  echo ""
  # Put it in the scripts/setup folder by default
  export PROPERTIES_FILE="${SCRIPTS_DIR}/${filename}"

  # User entered an absolute path (probabaly)
  starts_with "$filename" "/" && export PROPERTIES_FILE="$filename"
}


process_args()
{
  while getopts "t:f:?" opt
  do
    case "$opt" in
      t)
        VERSION_TAG=${OPTARG}
        ;;
      f)
        PROPERTIES_FILE="${OPTARG}"
        ;;
      *)
        echo "-- What? --"
        usage
        ;;
    esac
  done
}

Main()
{
  process_args "$@"
  intro
  configure_deployment_platform
  configure_namespace
  configure_encryption_keyfile
  configure_registry_credentials
  configure_reverse_proxy
  configure_tls_certificate
  get_property_file_name
  save_properties_file
  deploy_enterprise_admin
  cleanup 0
}

Main "$@"
