
# common.sh
#
# This script should not be run.  It is sourced by the installer
# scripts to provide common functions shared by these scripts
#

ARCGIS_VERSION="ArcGIS 2021"
PRODUCT_NAME="ArcGIS Enterprise on Kubernetes"
PRODUCT_VERSION="10.9.1"
SCRIPT_VERSION="0.1.3"

# Base 10
ONE_KB=1000
ONE_MB=$(( $ONE_KB * $ONE_KB ))
ONE_GB=$(( $ONE_MB * $ONE_KB ))
ONE_TB=$(( $ONE_GB * $ONE_KB ))

# Base 2
ONE_KIB=1024
ONE_MIB=$(( $ONE_KIB * $ONE_KIB ))
ONE_GIB=$(( $ONE_MIB * $ONE_KIB ))
ONE_TIB=$(( $ONE_GIB * $ONE_KIB ))

# For checking if the terminal supports color and ANSI escape sequences
HAS_TTY=true
tty -s || HAS_TTY=false

# --------------------------------------------------------------
# GUI Stuff
# --------------------------------------------------------------

BLACK=0
RED=1
GREEN=2
YELLOW=3
BLUE=4
MAGENTA=5
CYAN=6
WHITE=7
GREY=8

if [ "$HAS_TTY" = true ]; then
  fg_black=$(tput setaf $BLACK)
  fg_red=$(tput setaf $RED)
  fg_green=$(tput setaf $GREEN)
  fg_yellow=$(tput setaf $YELLOW)
  fg_blue=$(tput setaf $BLUE)
  fg_magenta=$(tput setaf $MAGENTA)
  fg_cyan=$(tput setaf $CYAN)
  fg_white=$(tput setaf $WHITE)
  fg_grey=$(tput setaf $GREY)
  fg_bold=$(tput bold)
  txt_reset=$(tput sgr0)
else
  fg_black=""
  fg_red=""
  fg_green=""
  fg_yellow=""
  fg_blue=""
  fg_magenta=""
  fg_cyan=""
  fg_white=""
  fg_grey=""
  fg_bold=""
  txt_reset=""
fi

has_tty()
{
  [ "$HAS_TTY" = true ]
}

fg()
{
  [ "$HAS_TTY" = true ] && tput setaf $1
}
bg()
{
  [ "$HAS_TTY" = true ] && tput setab $1
}

draw_line()
{
  local _HLINE="─"

  if [ "$HAS_TTY" = true ]; then
    for i in $(seq 1 79) ; do echo -ne $_HLINE; done
    echo ""
  else
    printf -v line "%*s" 79 && echo "${line// /-}"
  fi
}

draw_ellipses()
{
  local width=$1
  printf -v line "%*s" $width && printf "${line// /.}"
}

print_center()
{
  local text="$1"
  local max_width="$2"

  [ -z "$2" ] && max_width="79"

  local width=${#text}
  local start_col=$(( ($max_width - $width) / 2 ))

  printf "%${start_col}s%s\n" '' "$text"
}

text_bold()
{
  $(has_tty) && tput bold
}

text_reverse()
{
  $(has_tty) && tput rev
}

text_normal()
{
  $(has_tty) && tput sgr0
}

header()
{
  draw_line
  text_bold
  echo "$1"
  text_normal
  draw_line
}

success()
{
  $(has_tty) && {
    echo "[${fg_green}SUCCESS${txt_reset}]"
  } || {
    echo "SUCCESS"
  }
}

note()
{
  echo ""
  $(has_tty) && {
    printf "${fg_cyan}NOTE:${txt_reset}"
  } || {
    printf "NOTE:"
  }
  printf " %s\n" "$1" | fmt -w 79
  echo ""
}

warning()
{
  echo ""
  $(has_tty) && {
    printf "${fg_yellow}WARNING:${txt_reset}"
  } || {
    printf "WARNING:"
  }
  printf " %s\n" "$1" | fmt -w 79
  echo ""
}

alert()
{
  echo ""
  $(has_tty) && {
    printf "${fg_magenta}ALERT:${txt_reset}"
  } || {
    printf "ALERT:"
  }
  printf " %s\n" "$1" | fmt -w 79
  echo ""
}

ccat()
{
  cat "$1" | grep -Ev "^#|^$" # Cat file and strip blanks and comments
}

# --------------------------------------------------------------
# User question prompts
# --------------------------------------------------------------
error_msg()
{
  local msg="$1"
  $(has_tty) && {
    printf "    - ${fg_red}%s${txt_reset}" "$msg" | fmt
  } || {
    printf "    - %s" "$msg"
  }
  printf "\n"
  sleep 1
}

warning_msg()
{
  local msg="$1"
  $(has_tty) && {
    printf "    - ${fg_yellow}%s${txt_reset}" "$msg"
  } || {
    printf "    - %s" "$msg"
  }
  printf "\n"
  sleep 1
}

error_prompt()
{
  local msg="$1"
  $(has_tty) && {
    printf "    - ${fg_red}%s${txt_reset}" "$msg"
  } || {
    printf "    - %s" "$msg"
  }
}

section_header()
{
  local msg="$1"
  local color="${fg_blue}"

  [ -n "$2" ] && color="$2"

  echo ""
  draw_line
  text_bold
  printf "${color}%s${txt_reset}\n" "$msg"
  text_normal
}

section_description()
{
  local msg="$1"

  echo ""
  text_normal
  printf "%s" "$msg" | fmt -w 79
  draw_line  
}

section_prompt()
{
  local msg="$1"

  echo ""
  echo "$msg" | fmt | sed 's/^/    /g'
  echo ""
}

prompt()
{
  local msg="$1"
  local default="$2"

  if [ -n "$default" ]; then
    printf "    - %s (default=${fg_bold}%s${txt_reset}) : " "$msg" "$default"
  else
    printf "    - %s : " "$msg"
  fi
}


# --------------------------------------------------------------
# Misc
# --------------------------------------------------------------
echo_dbg()
{
  [ "$DEBUG" = true ] && echo "$1"
}

file_exists()
{
  [ -f "$1" ]
}

is_yes()
{
  local answer=$(echo $1 | tr '[A-Z]' '[a-z]')
  case "$answer" in
    y|yes|ok|true|1) true ;;
    *) false ;;
  esac
}

is_no()
{
  local answer=$(echo $1 | tr '[A-Z]' '[a-z]')
  case "$answer" in
    n|no|nope|false|0) true ;;
    *) false ;;
  esac
}

str_contains()
{
  local string="$1"
  local tofind="$2"

  [[ -n "$tofind" ]] && [[ $string =~ $tofind ]]
}

has_spaces()
{
  local string="$1"

  local re="[[:space:]]+"
  [[ $string =~ $re ]]
}

has_digits()
{
  local num="$1"
  [[ $num =~ [[:digit:]] ]]
}

has_digits_only()
{
  local num="$1"
  [[ $num =~ ^[0-9]+$ ]]
}

starts_with()
{
  local string="$1"
  local match="$2"

  [[ $string == $match* ]]
}

clear_line()
{
  # Erase prompt in tty mode
  $(has_tty) && {
    tput cuu1
    tput el
    echo -e "\r"
  }
}

press_a_key()
{
  [ "$INTERACTIVE" = false ] && return
  echo ""
  echo -n "$1"
  read -s -n 1 key

  clear_line
}

edit_in_file()
{
  local sed_string="$1"
  local file="$2"

  [ ! -f "$file" ] && return

  # MacOSX's version of sed's -i flag requires a backup extension
  # argument so just supply an empty string.
  #
  if [ "$(uname -s)" = "Darwin" ]; then
    sed -i '' "$sed_string" "${file}"
  else
    sed -i "$sed_string" "${file}"
  fi
}

# Handle base64 -d flag on MacOS
decode64()
{
  local decode_flag="-d"

  [ "$(uname -s)" = "Darwin" ] && decode_flag="-D"

  echo "$1" | base64 $decode_flag
}

# Preserve sudo user's ownership during file operations (bash-only)
safe_touch()
{
  touch "$1"
  res=$?
  if [ $res -eq 0 ]; then
    [ -n "${SUDO_USER}" ] && chown "${SUDO_USER}:${SUDO_GID}" "$1"
  fi
  return $res
}

safe_mkdir()
{
  mkdir "$@"
  res=$?
  if [ $res -eq 0 ]; then
    [ -n "${SUDO_USER}" ] && chown -R "${SUDO_USER}:${SUDO_GID}" "${@: -1}"
  fi
  return $res
}

safe_cp()
{
  cp "$@"
  res=$?
  if [ $res -eq 0 ]; then
    [ -n "${SUDO_USER}" ] && chown -R "${SUDO_USER}:${SUDO_GID}" "${@: -1}"
  fi
  return $res
}

safe_ln()
{
  ln "$@"
  res=$?
  if [ $res -eq 0 ]; then
    [ -n "${SUDO_USER}" ] && chown -R "${SUDO_USER}:${SUDO_GID}" "${@: -1}"
  fi
  return $res
}


# Number conversions
kb_to_gb()
{
  local kb="$1"

  ret=$(awk -v k="$kb" -v m="$ONE_MB" 'BEGIN { printf "%.1fG", k / m }')
  echo "$ret"
}

secs_to_min_sec()
{
  local secs="$1"
  printf "%02dm:%02ds" "$(($secs%3600/60))" "$(($secs%60))"
}

secs_to_hour_min_sec()
{
  local secs="$1"
  printf "%02dh:%02dm:%02ds" "$(($secs/3600))" "$(($secs%3600/60))" "$(($secs%60))"
}

# https://www.linuxjournal.com/content/validating-ip-address-bash-script
is_valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# https://stackoverflow.com/a/26850032
is_valid_fqdn()
{
  local fqdn="$1"
  local res=""

  # strip any port number
  fqdn=$(echo ${fqdn} | cut -d: -f1)

  if [ "$(uname -s)" = "Darwin" ]; then
    res=$(echo $fqdn | perl -lne 'print $1 if /(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)/')
  else
    res=$(echo $fqdn | grep -P '(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)')
  fi
  [ -n "$res" ]
}

mask_command()
{
  local command="$1"
  local mask="$2"

  if [ -z "$mask" ]; then
    echo "${command}"
    return
  fi

  echo "${command}" | sed "s^${mask}^\*\*\*\*\*\*^g"
}

is_base64()
{
  local str="$1"
  local res=""

  # https://stackoverflow.com/a/49153439
  if [ "$(uname -s)" = "Darwin" ]; then
    res=$(echo $str | perl -lne 'print $1 if /^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/')
  else
    res=$(echo $str | grep -P '(^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$)')
  fi
  [ -n "$res" ]
}

encode_base64()
{
  local str="$1"

  echo "$str" | base64
}

decode_base64()
{
  local str="$1"
  local res=""

  if [ "$(uname -s)" = "Darwin" ]; then
    res=$(echo "$str" | base64 -D)
  else
    res=$(echo "$str" | base64 -d)
  fi
  echo "$res"
}

can_encrypt_aes256_string()
{
  local str="$1"
  local keyfile="$2"

  echo "$str" | openssl enc -e -aes256 -pbkdf2 -pass file:"${keyfile}" -base64 > /dev/null 2>&1
  [ $? -eq 0 ]
}

can_decrypt_aes256_string()
{
  local str="$1"
  local keyfile="$2"

  echo "$str" | openssl enc -d -aes256 -pbkdf2 -pass file:"${keyfile}" -base64 > /dev/null 2>&1
  [ $? -eq 0 ]
}

get_encrypted_aes256_string()
{
  local str="$1"
  local keyfile="$2"
  local res=""

  res=$(echo "$str" | openssl enc -e -aes256 -pbkdf2 -pass file:"${keyfile}" -base64)
  echo "$res"
}

get_decrypted_aes256_string()
{
  local str="$1"
  local keyfile="$2"
  local res=""

  res=$(echo "$str" | openssl enc -d -aes256 -pbkdf2 -pass file:"${keyfile}" -base64)
  echo "$res"
}

