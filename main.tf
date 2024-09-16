terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.61"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13"
    }
    kubectl = {
      source  = "alekc/kubectl"
      version = ">= 2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.32"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12"
    }
  }
}

provider "aws" {
  region = local.region
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = local.cluster_ca_certificate

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
    }
  }
}

provider "kubectl" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = local.cluster_ca_certificate

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = local.cluster_ca_certificate
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
  }
}

provider "time" {}

variable "use_fixed_velero_policy" {
  description = "Whether to use the corrected IAM policy for Velero"
  type        = bool
}

data "aws_availability_zones" "available" {}

locals {
  name   = "velero-mre"
  region = "us-east-2"

  vpc_cidr = "10.42.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  tags = {
    app = local.name
    env = "test"
  }
}

######
# VPC
######

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  intra_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 52)]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}

######
# EKS
######

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.24.0"

  cluster_name    = local.name
  cluster_version = "1.30"

  cluster_addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni    = {}
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_cluster_creator_admin_permissions = true
  cluster_endpoint_public_access           = true

  eks_managed_node_groups = {
    example = {
      ami_type       = "AL2_x86_64"
      instance_types = ["m6i.large"]

      min_size     = 2
      max_size     = 3
      desired_size = 2
    }
  }

  tags = local.tags
}

#####################
# AWS EBS CSI Driver
#####################

resource "aws_kms_key" "ebs" {
  description             = "Key to encrypt EBS volumes in ${local.name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.name}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.44.0"

  create_role = true

  role_name             = "ebs-csi-irsa-${local.name}"
  attach_ebs_csi_policy = true

  ebs_csi_kms_cmk_ids = [aws_kms_key.ebs.arn]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = [
        "aws-ebs-csi-driver:ebs-csi-controller-sa",
        "aws-ebs-csi-driver:ebs-csi-node-sa",
      ]
    }
  }

  tags = local.tags
}

resource "helm_release" "ebs_csi_driver" {
  depends_on = [module.eks]

  namespace        = "aws-ebs-csi-driver"
  create_namespace = true

  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver/"
  chart      = "aws-ebs-csi-driver"
  version    = "2.32.0"

  values = [
    templatefile("${path.root}/values.aws-ebs-csi-driver.yaml", {
      cluster_name = local.name,
      region = local.region,
      iam_role_arn = module.ebs_csi_irsa.iam_role_arn,
      kms_key_arn = aws_kms_key.ebs.arn,
  })]
}

######################
# Snapshot Controller
######################

resource "helm_release" "snapshot_controller" {
  depends_on = [module.eks]

  namespace        = "snapshot-controller"
  create_namespace = true

  name       = "snapshot-controller"
  repository = "https://piraeus.io/helm-charts"
  chart      = "snapshot-controller"
  version    = "3.0.5"
}

#########
# Velero
#########

module "velero_backup_s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "velero-backups-${local.name}"

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  acl = "private"

  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  versioning = {
    status     = true
    mfa_delete = false
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.tags
}

module "velero_irsa_broken" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.44.0"

  count = var.use_fixed_velero_policy ? 0 : 1

  create_role = true

  role_name             = "velero-irsa-${local.name}-broken"
  attach_velero_policy  = true
  velero_s3_bucket_arns = [module.velero_backup_s3_bucket.s3_bucket_arn]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["velero:velero-server"]
    }
  }

  tags = local.tags
}

module "velero_irsa_fixed" {
  source  = "git@github.com:chrisRedwine/terraform-aws-iam.git//modules/iam-role-for-service-accounts-eks?depth=1&ref=master"

  count = var.use_fixed_velero_policy ? 1 : 0

  create_role = true

  role_name             = "velero-irsa-${local.name}-fixed"
  attach_velero_policy  = true
  velero_s3_bucket_arns = [module.velero_backup_s3_bucket.s3_bucket_arn]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["velero:velero-server"]
    }
  }

  tags = local.tags
}

resource "kubectl_manifest" "volume_snapshot_class" {
  depends_on = [helm_release.ebs_csi_driver]

  yaml_body = <<YAML
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: ebs-csi-vsc
  labels:
    velero.io/csi-volumesnapshot-class: 'true'
deletionPolicy: Retain
driver: ebs.csi.aws.com
YAML
}

resource "helm_release" "velero" {
  depends_on = [kubectl_manifest.volume_snapshot_class]

  namespace        = "velero"
  create_namespace = true

  name       = "velero"
  repository = "https://vmware-tanzu.github.io/helm-charts"
  chart      = "velero"
  version    = "7.2.1"

  values = [
    templatefile("${path.root}/values.velero.yaml", {
      region       = local.region,
      bucket       = module.velero_backup_s3_bucket.s3_bucket_id,
      tagging      = join("&", [for key, value in local.tags : "${key}=${value}"]),
      iam_role_arn = var.use_fixed_velero_policy ? module.velero_irsa_fixed[0].iam_role_arn : module.velero_irsa_broken[0].iam_role_arn,
  })]

  wait = true
}

# Restart Velero pods to apply the new IRSA policy
resource "time_static" "restarted_at" {
  triggers = {
    velero_irsa = var.use_fixed_velero_policy
  }
}

resource "kubernetes_annotations" "velero_restart" {
  depends_on = [helm_release.velero]

  api_version = "apps/v1"
  kind        = "Deployment"
  metadata {
    name = "velero"
    namespace = "velero"
  }
  template_annotations = {
    "kubectl.kubernetes.io/restartedAt" = time_static.restarted_at.rfc3339
  }
  force = true
}

resource "kubernetes_annotations" "velero_node_agent_restart" {
  depends_on = [helm_release.velero]

  api_version = "apps/v1"
  kind        = "DaemonSet"
  metadata {
    name = "node-agent"
    namespace = "velero"
  }
  template_annotations = {
    "kubectl.kubernetes.io/restartedAt" = time_static.restarted_at.rfc3339
  }
  force = true
}

##########
# PVC/Pod
##########

resource "kubectl_manifest" "ebs_pvc" {
  depends_on = [helm_release.ebs_csi_driver]

  yaml_body = <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ebs-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ebs-csi
  resources:
    requests:
      storage: 1Gi
YAML
}

resource "kubectl_manifest" "ebs_pvc_pod" {
  depends_on = [helm_release.ebs_csi_driver]

  yaml_body = <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ebs-pvc-pod
spec:
  containers:
    - name: main
      image: busybox
      command: ["/bin/sh", "-c"]
      args:
        - |
          echo "Hello from EBS" > /data/hello.txt;
          cat /data/hello.txt;
          sleep 3600;
      volumeMounts:
        - name: ebs-volume
          mountPath: /data
  volumes:
    - name: ebs-volume
      persistentVolumeClaim:
        claimName: ebs-pvc
YAML
}
