# Earthly BYOC

This module allows you to provision the infrastructure needed for an Earthly BYOC deployment. Once this is applied, follow our Terraform documentation to finish your installation.

### Module Inputs

| Name           | Description                                                                                                                                              |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| cloud_name     | The name to use to identify the cloud installation. Used by Earthly during automatic installation, and to mark related resources in AWS.                 |
| subnet         | The subnet Earthly will deploy satellites into.                                                                                                          |
| ssh_public_key | (Optional) The SSH key to include in provisioned satellites. If left unspecified, a new key is generated, and the private key is available as an output. |


### Module Outputs

| Name                 | Description                                                                                                                              |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| installation_name    | The name to use to identify the cloud installation. Used by Earthly during automatic installation, and to mark related resources in AWS. |
| security_group_id    | The ID of the security group for new satellites.                                                                                         |
| ssh_key_name         | The name of the SSH key in AWS that is included in new satellites.                                                                       |
| ssh_private_key      | (Sensitive) The private key, if `ssh_public_key` is unspecified.                                                                         |
| instance_profile_arn | The ARN of the instance profile satellite instances will use for logging.                                                                |
| compute_role_arn     | The ARN of the role Earthly will assume to orchestrate satellites on your behalf.                                                        |
