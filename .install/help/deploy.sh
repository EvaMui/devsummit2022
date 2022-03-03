#!/bin/bash

PROG=$(basename "$0")
CWD="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="help"
YAML_ORIG="${CWD}/${BASE_NAME}.yaml"
RESOURCES="$(cd "${CWD}/../resources" && pwd)"
CUSTOM_PROPERTIES=""
YAML_TEMP="${RESOURCES}/tmp/${BASE_NAME}.yaml.$$.tmp"
PROPERTIES="${CWD}/../arcgis-enterprise/arcgis-enterprise.properties"
VERBOSE=${VERBOSE:-false}

DEPLOY=true

usage()
{
  echo "Usage: ${PROG} [-u] [${BASE_NAME}.properties]"
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

cleanup()
{
  rm -f "${YAML_TEMP}"
}

init_temp_dir()
{
  [ "$HELM_DEPLOY" = true ] && {
    YAML_TEMP="/arcgistmp/${BASE_NAME}.yaml.$$.tmp"
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

  [ ! -f "$PROPERTIES" ] && {
    fail "Properties file $PROPERTIES does not exist."
  }
}

generate_yaml()
{
  echo_d ""
  echo_d "Using input properties:"

  echo_d "  PROPERTIES = $PROPERTIES"
  echo_d "  DEPLOY = $DEPLOY"

  cp -p "$YAML_ORIG" "$YAML_TEMP"

  while IFS= read line
  do
    var=$(echo "$line" | cut -d= -f1)
    val=${!var}

    grep -q -w "${var}" "${YAML_ORIG}"
    if [ $? -eq 0 ]; then
      if [ "$(uname -s)" = "Darwin" ]; then
        sed -i '' 's^${'${var}'}^'${val}'^g' "${YAML_TEMP}"
      else
        sed -i 's^${'${var}'}^'${val}'^g' "${YAML_TEMP}"
      fi

      echo_d "  ${var} = ${val}"
    fi

  done < <(cat "$PROPERTIES" | grep -Ev "^#|^$")
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

  init_temp_dir
  generate_yaml
  apply_yaml
  cleanup
}

Main "$@"
