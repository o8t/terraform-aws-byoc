data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_subnet" "current" {
  id = var.subnet
}
