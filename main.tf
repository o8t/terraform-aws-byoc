locals {
  tags = {
    earthly-cloud = var.cloud_name
  }
}

## ---------------------------------------------------------------------------------------------------------------------
## SSH KEY FOR DEBUG ACCESS TO SATELLITES
## Creates a new SSH key if one is not provided; or uses the user provided one to create the key pair in AWS. This key
## will be included on the satellites at launch time so you can access them if needed.
## ---------------------------------------------------------------------------------------------------------------------

resource "tls_private_key" satellite {
  count = var.ssh_public_key == ""  ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" satellite_ssh_key {
  key_name = "${var.cloud_name}-satellite-key"
  public_key = (
    var.ssh_public_key == ""
    ? tls_private_key.satellite[0].public_key_openssh
    : var.ssh_public_key
  )
  tags = local.tags
}

## ---------------------------------------------------------------------------------------------------------------------
## BUILDKIT LOG GROUP
## The log driver for each satellites buildkit is configured to log to Cloudwatch.
## ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" satellite_logs {
  log_group_class = "STANDARD"
  name = "/earthly/satellites/${var.cloud_name}"
  tags = local.tags
}

## ---------------------------------------------------------------------------------------------------------------------
## SATELLITE SECURITY GROUP
## Satellites need some kind of access. User responsible for ensuring internet access (if needed). Opens ports for
## debug SSH access, Buildkit access, and Prometheus monitoring.
## ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" satellite_security_group {
  name = "${var.cloud_name}-satellites-access"
  description = "Minimal required rules for satellites."
  vpc_id = data.aws_subnet.current.vpc_id

  ingress {
      cidr_blocks = [data.aws_subnet.current.cidr_block]
      protocol = "tcp"
      description = "Allow SSH access from within the ingress subnet"
      from_port = 22
      to_port = 22
  }

  ingress {
      cidr_blocks = [data.aws_subnet.current.cidr_block]
      protocol = "tcp"
      description = "Allow Buildkit access from within the ingress subnet"
      from_port = 8372
      to_port = 8372
  }

  ingress {
      cidr_blocks = [data.aws_subnet.current.cidr_block]
      protocol = "tcp"
      description = "Allow Prometheus access from within the ingress subnet"
      from_port = 9000
      to_port = 9000
  }

  egress {
      cidr_blocks = ["0.0.0.0/0"]
      protocol = -1
      description = "Satellites have general outbound access to whatever they need"
      from_port = 0
      to_port = 0
    }

  tags = local.tags
}

## ---------------------------------------------------------------------------------------------------------------------
## SATELLITE INSTANCE ROLE
## Satellites need IAM permissions to allow Buildkit logs to CloudFormation.
## ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" satellite_instance_role {
  description = "The instance role for Satellites"
  path = "/earthly/satellites/${var.cloud_name}/"
  managed_policy_arns = [
    aws_iam_policy.satellite_instance_policy.arn
  ]
  max_session_duration = 3600
  name = "${var.cloud_name}-satellite-instance"
  assume_role_policy = data.aws_iam_policy_document.satellite_instance_assume_role_policy_document.json
  tags = local.tags
}

data aws_iam_policy_document satellite_instance_assume_role_policy_document {
  version = "2012-10-17"

  statement {
    actions = ["sts:AssumeRole"]
    effect = "Allow"
    principals {
      identifiers = ["ec2.amazonaws.com"]
      type = "Service"
    }
  }
}

resource "aws_iam_instance_profile" satellite_instance_profile {
  path = "/earthly/satellites/${var.cloud_name}/"
  role = aws_iam_role.satellite_instance_role.name
}

resource "aws_iam_policy" satellite_instance_policy {
  name = "${var.cloud_name}-satellite-policy"
  description = "The policy for the Satellite instance profile. Used to enable logging to Cloudwatch"
  path = "/earthly/satellites/${var.cloud_name}/"
  policy = data.aws_iam_policy_document.satellite_instance_policy_document.json
}

data aws_iam_policy_document satellite_instance_policy_document {
  version = "2012-10-17"
  statement {
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.satellite_logs.name}:log-stream:*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.satellite_logs.name}"
    ]
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream"
    ]
    effect = "Allow"
  }
}

## ---------------------------------------------------------------------------------------------------------------------
## EARTHLY ACCESS ROLE
## Earthly needs permissions to allow orchestration of satellite instances. This includes launching new satellites,
## updating existing ones, or sleeping/waking inactive ones.
## ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" earthly_access_role {
  description = "The role for satellite management"
  path = "/earthly/satellites/${var.cloud_name}/"
  managed_policy_arns = [
    aws_iam_policy.earthly_access_policy.arn
  ]
  max_session_duration = 3600
  name = "${var.cloud_name}-satellites"
  assume_role_policy = data.aws_iam_policy_document.earthly_access_assume_role_policy_document.json
  tags = local.tags
}

data aws_iam_policy_document earthly_access_assume_role_policy_document {
  version = "2012-10-17"
  statement {
      actions = ["sts:AssumeRole"]
      effect = "Allow"
      principals {
        identifiers = ["arn:aws:iam::404851345508:role/compute-production"]
        type = "AWS"
      }
  }
}

resource "aws_iam_policy" earthly_access_policy {
  name = "${var.cloud_name}-earthly-access-policy"
  path = "/earthly/satellites/${var.cloud_name}/"
  description = "This is the permissions that Earthly's compute management service needs to manage your satellites for you"
  policy = data.aws_iam_policy_document.earthly_access_policy_document.json
}

data "aws_iam_policy_document" earthly_access_policy_document {
  version = "2012-10-17"

  statement {
    resources = ["*"]
    actions = [
      "tag:GetResources",
      "iam:PassRole",
      "ec2:DescribeSubnets",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeImages"
    ]
    effect = "Allow"
  }

  statement {
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}::image/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:volume/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:security-group/${aws_security_group.satellite_security_group.id}",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:network-interface/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key-pair/${aws_key_pair.satellite_ssh_key.id}",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:subnet/${var.subnet}"
    ]
    actions = [
      "ec2:RunInstances",
      "ec2:ModifyInstanceAttribute"
    ]
    effect = "Allow"
  }

  statement {
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:volume/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:network-interface/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
    ]
    actions = [
      "ec2:RunInstances",
      "ec2:CreateVolume"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/earthly:application"
      values   = ["satellite"]
    }
    effect = "Allow"
  }

  statement {
    resources = ["arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"]
    actions = [
      "ec2:TerminateInstances",
      "ec2:StopInstances",
      "ec2:StartInstances"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/earthly:application"
      values   = ["satellite"]
    }
    effect = "Allow"
  }

  statement {
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:volume/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
    ]
    actions = [
      "ec2:DetachVolume",
      "ec2:DeleteVolume",
      "ec2:AttachVolume"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/earthly:application"
      values   = ["satellite"]
    }
    effect = "Allow"
  }

  statement {
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:volume/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*",
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:network-interface/*"
    ]
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances", "CreateVolume"]
    }
    effect = "Allow"
  }
}
