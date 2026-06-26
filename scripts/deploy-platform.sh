#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VALID_ENVS=("dev" "staging" "prod")

log() { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
  cat <<EOF
Usage: $(basename "$0") <environment>

Environments: ${VALID_ENVS[*]}

Options:
  -h, --help       Show this help
  -n, --dry-run    Dry run only
  -f, --force      Skip confirmation
  -v, --verbose    Verbose output
EOF
  exit 1
}

validate_env() {
  local env=$1
  for valid in "${VALID_ENVS[@]}"; do
    if [ "$env" = "$valid" ]; then
      return 0
    fi
  done
  return 1
}

check_prerequisites() {
  log "Checking prerequisites..."

  for cmd in kubectl kustomize aws; do
    if ! command -v "$cmd" &>/dev/null; then
      error "$cmd is required but not installed"
    fi
  done

  if ! kubectl cluster-info &>/dev/null; then
    error "Cannot connect to Kubernetes cluster"
  fi

  log "Prerequisites OK"
}

configure_kubectl() {
  local env=$1

  log "Configuring kubectl for $env..."
  aws eks update-kubeconfig \
    --name "cobalto-${env}" \
    --region "${AWS_REGION:-us-east-1}" \
    --kubeconfig "${KUBECONFIG:-$HOME/.kube/config}"

  kubectl config use-context "arn:aws:eks:${AWS_REGION:-us-east-1}:$(aws sts get-caller-identity --query Account --output text):cluster/cobalto-${env}"

  log "kubectl configured for $env"
}

build_manifests() {
  local env=$1
  local dry_run=$2

  log "Building Kustomize manifests for $env..."

  local overlay_dir="$REPO_ROOT/k8s/overlays/$env"
  if [ ! -d "$overlay_dir" ]; then
    error "Overlay directory not found: $overlay_dir"
  fi

  if [ "$dry_run" = "true" ]; then
    kustomize build "$overlay_dir" --dry-run=client
    log "Dry run complete"
  else
    kustomize build "$overlay_dir" > /tmp/cobalto-manifests.yaml
    log "Manifests built: /tmp/cobalto-manifests.yaml"
  fi
}

apply_manifests() {
  local env=$1

  log "Applying manifests to $env..."
  kubectl apply -f /tmp/cobalto-manifests.yaml -n cobalto --prune -l app.kubernetes.io/managed-by=kustomize

  log "Manifests applied"
}

wait_for_rollout() {
  local env=$1

  log "Waiting for deployments to roll out..."

  local deployments
  deployments=$(kubectl get deployments -n cobalto -o jsonpath='{.items[*].metadata.name}')

  for deploy in $deployments; do
    log "Waiting for $deploy..."
    if ! kubectl rollout status deployment/"$deploy" -n cobalto --timeout=300s; then
      error "Rollout failed for $deploy"
    fi
    log "$deploy rolled out successfully"
  done

  local statefulsets
  statefulsets=$(kubectl get statefulsets -n cobalto -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)

  for sts in $statefulsets; do
    log "Waiting for $sts..."
    if ! kubectl rollout status statefulset/"$sts" -n cobalto --timeout=300s; then
      error "Rollout failed for $sts"
    fi
    log "$sts rolled out successfully"
  done

  log "All rollouts complete"
}

validate_health() {
  local env=$1

  log "Validating health checks..."

  local all_healthy=true

  # Check pod status
  local unhealthy_pods
  unhealthy_pods=$(kubectl get pods -n cobalto \
    -o jsonpath='{range .items[?(@.status.phase!="Running")]}{.metadata.name}{"\n"}{end}')

  if [ -n "$unhealthy_pods" ]; then
    warn "Unhealthy pods detected:"
    echo "$unhealthy_pods"
    all_healthy=false
  fi

  # Check services have endpoints
  local services
  services=$(kubectl get svc -n cobalto -o jsonpath='{.items[*].metadata.name}')

  for svc in $services; do
    local endpoints
    endpoints=$(kubectl get endpoints "$svc" -n cobalto -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)
    if [ -z "$endpoints" ]; then
      warn "Service $svc has no endpoints"
      all_healthy=false
    fi
  done

  # Check for recent restarts
  local restarts
  restarts=$(kubectl get pods -n cobalto \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}' | \
    awk -F'\t' '$2 > 3 {print $1}')

  if [ -n "$restarts" ]; then
    warn "Pods with excessive restarts:"
    echo "$restarts"
    all_healthy=false
  fi

  if [ "$all_healthy" = "false" ]; then
    warn "Health validation completed with warnings"
    return 1
  fi

  log "All health checks passed"
  return 0
}

print_summary() {
  local env=$1

  echo
  echo "=== Deployment Summary ==="
  echo "Environment: $env"
  echo "Namespace:   cobalto"
  echo "Context:     $(kubectl config current-context)"
  echo
  echo "Deployments:"
  kubectl get deployments -n cobalto -o wide
  echo
  echo "Services:"
  kubectl get svc -n cobalto -o wide
  echo
  echo "Pods:"
  kubectl get pods -n cobalto -o wide
}

main() {
  local env=""
  local dry_run="false"
  local force="false"

  while [ $# -gt 0 ]; do
    case $1 in
      -h|--help) usage ;;
      -n|--dry-run) dry_run="true"; shift ;;
      -f|--force) force="true"; shift ;;
      -v|--verbose) set -x; shift ;;
      -*) error "Unknown option: $1" ;;
      *) env=$1; shift ;;
    esac
  done

  if [ -z "$env" ]; then
    usage
  fi

  if ! validate_env "$env"; then
    error "Invalid environment: $env. Valid: ${VALID_ENVS[*]}"
  fi

  log "=== Deploying Cobalto Platform to $env ==="

  check_prerequisites
  configure_kubectl "$env"
  build_manifests "$env" "$dry_run"

  if [ "$dry_run" = "true" ]; then
    log "Dry run complete. No changes applied."
    exit 0
  fi

  if [ "$force" != "true" ] && [ "$env" = "prod" ]; then
    read -rp "Are you sure you want to deploy to PROD? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
      error "Deployment cancelled"
    fi
  fi

  apply_manifests "$env"
  wait_for_rollout "$env"
  validate_health "$env"
  print_summary "$env"

  log "=== Deployment Complete ==="
}

main "$@"
