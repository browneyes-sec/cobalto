#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { ((PASS++)); echo -e "${GREEN}✓${NC} $1"; }
fail() { ((FAIL++)); echo -e "${RED}✗${NC} $1"; }
warn() { ((WARN++)); echo -e "${YELLOW}⚠${NC} $1"; }

validate_terraform_fmt() {
  log "Terraform format check..."
  cd "$REPO_ROOT/terraform"

  if terraform fmt -check -recursive . 2>/dev/null; then
    pass "Terraform format"
  else
    fail "Terraform format - run 'terraform fmt -recursive'"
  fi
}

validate_terraform_validate() {
  log "Terraform validation..."
  cd "$REPO_ROOT/terraform"

  if terraform init -backend=false -input=false >/dev/null 2>&1 && \
     terraform validate 2>/dev/null; then
    pass "Terraform validate"
  else
    fail "Terraform validate"
  fi
}

validate_terraform_plan() {
  log "Terraform plan (no changes)..."
  cd "$REPO_ROOT/terraform"

  terraform init -backend=false -input=false >/dev/null 2>&1 || true

  local output
  if output=$(terraform plan -input=false -detailed-exitcode -no-color 2>&1); then
    pass "Terraform plan - no changes"
  else
    local exit_code=$?
    if [ "$exit_code" -eq 2 ]; then
      warn "Terraform plan detected changes"
    else
      fail "Terraform plan"
    fi
  fi
}

validate_kustomize() {
  log "Kustomize build validation..."

  local overlays_dir="$REPO_ROOT/k8s/overlays"
  if [ ! -d "$overlays_dir" ]; then
    warn "Kustomize overlays directory not found: $overlays_dir"
    return
  fi

  local all_pass=true
  for env in dev staging prod; do
    local dir="$overlays_dir/$env"
    if [ -d "$dir" ]; then
      if kustomize build "$dir" --dry-run=client >/dev/null 2>&1; then
        pass "Kustomize build: $env"
      else
        fail "Kustomize build: $env"
        all_pass=false
      fi
    fi
  done

  # Validate base
  local base_dir="$REPO_ROOT/k8s/base"
  if [ -d "$base_dir" ]; then
    if kustomize build "$base_dir" --dry-run=client >/dev/null 2>&1; then
      pass "Kustomize build: base"
    else
      fail "Kustomize build: base"
    fi
  fi
}

validate_python() {
  log "Python compilation check..."

  local agent_dir="$REPO_ROOT/langgraph-agent"
  if [ ! -d "$agent_dir" ]; then
    warn "langgraph-agent directory not found"
    return
  fi

  local py_files
  py_files=$(find "$agent_dir" -name "*.py" -type f 2>/dev/null)

  if [ -z "$py_files" ]; then
    warn "No Python files found in langgraph-agent"
    return
  fi

  local has_error=false
  while IFS= read -r file; do
    if python3 -m py_compile "$file" 2>/dev/null; then
      pass "py_compile: $(basename "$file")"
    else
      fail "py_compile: $(basename "$file")"
      has_error=true
    fi
  done <<< "$py_files"
}

validate_scripts() {
  log "Script syntax check..."

  local scripts_dir="$REPO_ROOT/scripts"
  if [ ! -d "$scripts_dir" ]; then
    warn "Scripts directory not found"
    return
  fi

  for script in "$scripts_dir"/*.sh; do
    if [ -f "$script" ]; then
      if bash -n "$script" 2>/dev/null; then
        pass "bash -n: $(basename "$script")"
      else
        fail "bash -n: $(basename "$script")"
      fi
    fi
  done
}

validate_yaml() {
  log "YAML lint..."

  local yaml_files
  yaml_files=$(find "$REPO_ROOT" \
    -name "*.yaml" -o -name "*.yml" | \
    grep -v node_modules | grep -v .git | head -50)

  if [ -z "$yaml_files" ]; then
    warn "No YAML files found"
    return
  fi

  if command -v yamllint &>/dev/null; then
    local has_error=false
    while IFS= read -r file; do
      if yamllint -d "{extends: relaxed, rules: {line-length: disable}}" "$file" 2>/dev/null; then
        pass "yamllint: $(basename "$file")"
      else
        fail "yamllint: $(basename "$file")"
        has_error=true
      fi
    done <<< "$yaml_files"
  else
    warn "yamllint not installed, skipping YAML validation"
  fi
}

print_summary() {
  echo
  echo "=== Validation Summary ==="
  echo -e "${GREEN}Passed:${NC} $PASS"
  echo -e "${RED}Failed:${NC} $FAIL"
  echo -e "${YELLOW}Warnings:${NC} $WARN"
  echo

  if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}VALIDATION FAILED${NC}"
    exit 1
  else
    echo -e "${GREEN}ALL CHECKS PASSED${NC}"
    exit 0
  fi
}

main() {
  log "=== Cobalto Platform Validation ==="

  validate_terraform_fmt
  validate_terraform_validate
  validate_terraform_plan
  validate_kustomize
  validate_python
  validate_scripts
  validate_yaml

  print_summary
}

main "$@"
