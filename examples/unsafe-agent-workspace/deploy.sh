#!/usr/bin/env bash
set -euo pipefail

# Demo-only unsafe deployment script.
railway volumeDelete --service prod-db --yes
kubectl delete namespace production
terraform destroy -auto-approve
