#!/bin/bash

PROG=$(basename "$0")
CWD="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="nfs-static-volume"
YAML_ORIG="${CWD}/${BASE_NAME}.yaml"
PROPERTIES="${CWD}/${BASE_NAME}.properties"
RESOURCES="$(cd "${CWD}/../resources" && pwd)"
CUSTOM_PROPERTIES=""
YAML_TEMP="${RESOURCES}/tmp/${BASE_NAME}.yaml.$$.tmp"

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
  echo ""
  echo "Using input properties:"

  echo "  PROPERTIES = $PROPERTIES"
  echo "  DEPLOY = $DEPLOY"

  cp -p "$YAML_ORIG" "$YAML_TEMP"

  while IFS= read line
  do
    var=$(echo "$line" | cut -d= -f1)
    val=${!var}

    if [ "$(uname -s)" = "Darwin" ]; then
      sed -i '' 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
    else
      sed -i 's^${'${var}'}^'"${val}"'^g' "${YAML_TEMP}"
    fi

    echo "  ${var} = ${val}"

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
    echo "Sourcing custom properties file: $CUSTOM_PROPERTIES"
    . "$CUSTOM_PROPERTIES"

    # Re-source the default properties files so variables using any new values are re-evaluated
    . "$PROPERTIES"

    # Re-source custom properties again so those values are re-evaluated
    . "$CUSTOM_PROPERTIES"
  }

  generate_yaml
  apply_yaml
}


Main "$@"

