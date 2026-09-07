#!/usr/bin/env bash
#
# Readers for tasks.list, the single source of truth for gate task names,
# plus the one JDK-home resolver every script must use.
#
# Source this; do not execute it.

_JOSTLE_TASKS_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
JOSTLE_TASKS_FILE="$_JOSTLE_TASKS_LIB_DIR/tasks.list"

# jostle_tasks <role> -> the tasks carrying that role, one per line, in file order.
jostle_tasks () {
  awk -v want="$1" '
    /^#/ || NF == 0 { next }
    { n = split($2, roles, ",")
      for (i = 1; i <= n; i++) { if (roles[i] == want) { print $1 } } }
  ' "$JOSTLE_TASKS_FILE"
}

# jostle_task_env <task> -> the env var gating it, or empty when ungated.
jostle_task_env () {
  awk -v want="$1" '
    /^#/ || NF == 0 { next }
    $1 == want { if ($3 != "-") { print $3 } }
  ' "$JOSTLE_TASKS_FILE"
}

# jostle_env_vars -> every distinct gating var named in the file.
jostle_env_vars () {
  awk '!/^#/ && NF && $3 != "-" { print $3 }' "$JOSTLE_TASKS_FILE" | sort -u
}

# jostle_jdk_home <path> -> a directory containing bin/java, or empty.
#
# A BC_JDK root may be flat or a macOS bundle (Contents/Home). Gradle copes
# with both; a shell building "$root/bin/java" does not. Resolve through here.
jostle_jdk_home () {
  local root="${1:-}"
  if [ -z "$root" ]; then
    return 1
  fi
  if [ -x "$root/bin/java" ]; then
    printf '%s\n' "$root"
    return 0
  fi
  if [ -x "$root/Contents/Home/bin/java" ]; then
    printf '%s\n' "$root/Contents/Home"
    return 0
  fi
  return 1
}
