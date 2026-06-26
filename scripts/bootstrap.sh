#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[COBALTO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_command() {
  command -v "$1" &>/dev/null
}

install_command() {
  local cmd=$1
  local pkg=${2:-$1}

  if check_command "$cmd"; then
    log "$cmd already installed"
    return
  fi

  log "Installing $pkg..."
  case "$cmd" in
    terraform)
      sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
      wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
      echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
      sudo apt-get update && sudo apt-get install -y terraform
      ;;
    kubectl)
      curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
      chmod +x kubectl && sudo mv kubectl /usr/local/bin/
      ;;
    helm)
      curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
      ;;
    aws)
      curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
      unzip -q awscliv2.zip && sudo ./aws/install && rm -rf aws awscliv2.zip
      ;;
    docker)
      sudo apt-get update
      sudo apt-get install -y ca-certificates curl gnupg
      sudo install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
      sudo usermod -aG docker "$USER"
      ;;
    flux)
      curl -s https://fluxcd.io/install.sh | sudo bash
      ;;
  esac
}

configure_aws() {
  log "Configuring AWS credentials..."

  if [ -f "$HOME/.aws/credentials" ]; then
    log "AWS credentials file found"
    return
  fi

  read -rp "AWS Access Key ID: " AWS_ACCESS_KEY_ID
  read -rsp "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
  echo
  read -rp "AWS Region [us-east-1]: " AWS_REGION
  AWS_REGION=${AWS_REGION:-us-east-1}

  mkdir -p "$HOME/.aws"
  cat > "$HOME/.aws/config" <<EOF
[default]
region = $AWS_REGION
output = json
EOF

  cat > "$HOME/.aws/credentials" <<EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY
EOF

  chmod 600 "$HOME/.aws/credentials"
  log "AWS credentials configured"
}

init_terraform() {
  log "Initializing Terraform..."
  cd "$REPO_ROOT/terraform"

  terraform init -upgrade

  if [ ! -f "terraform.tfvars" ]; then
    warn "terraform.tfvars not found. Copying from example..."
    if [ -f "terraform.tfvars.example" ]; then
      cp terraform.tfvars.example terraform.tfvars
      log "Edit terraform.tfvars with your values before proceeding"
    fi
  fi

  log "Terraform initialized"
}

create_eks_cluster() {
  log "Creating EKS cluster..."

  cd "$REPO_ROOT/terraform"
  terraform plan -out=tfplan
  terraform apply -input=false tfplan

  CLUSTER_NAME=$(terraform output -raw cluster_name)
  REGION=$(terraform output -raw region)

  aws eks update-kubeconfig \
    --name "$CLUSTER_NAME" \
    --region "$REGION" \
    --kubeconfig "$HOME/.kube/config"

  log "EKS cluster created and kubeconfig updated"
}

install_flux() {
  log "Installing Flux CD..."

  if ! check_command flux; then
    error "flux not found. Run this script again after installation."
  fi

  flux check --pre || error "Flux pre-flight check failed"

  cd "$REPO_ROOT"

  flux bootstrap github \
    --owner="$GITHUB_ORG" \
    --repository="cobalto-platform" \
    --branch=main \
    --path="./flux" \
    --personal

  log "Flux CD installed and bootstrapped"
}

main() {
  log "=== Cobalto SOC/MDR Platform Bootstrap ==="

  # Check/install dependencies
  log "Checking dependencies..."
  install_command terraform
  install_command kubectl
  install_command helm
  install_command aws
  install_command docker
  install_command flux

  # Verify installations
  log "Verifying installations..."
  for cmd in terraform kubectl helm aws docker flux; do
    if check_command "$cmd"; then
      log "$cmd: $(command -v "$cmd")"
    else
      error "$cmd installation failed"
    fi
  done

  # Configure AWS
  configure_aws

  # Initialize Terraform
  init_terraform

  # Create EKS cluster
  create_eks_cluster

  # Install Flux
  read -rp "Install Flux CD? (y/N): " INSTALL_FLUX
  if [[ "${INSTALL_FLUX,,}" == "y" ]]; then
    read -rp "GitHub organization/user: " GITHUB_ORG
    install_flux
  fi

  log "=== Bootstrap Complete ==="
  log "Kubeconfig: $HOME/.kube/config"
  log "Cluster context: $(kubectl config current-context 2>/dev/null || echo 'N/A')"
}

main "$@"
