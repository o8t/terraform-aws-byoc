variable cloud_name {
  description = "The name of the cloud installation."
  type = string
}

variable subnet {
  description = "The subnet that Earthly is allowed to launch satellites into."
  type = string
}

variable sg_cidr_override {
  description = "Overrides the CIDR used in security group rules for the satellites"
  type        = string
  default     = ""
}

variable ssh_public_key {
  description = "The public key to use when provisioning your satellites. No value generates a key for you and stores the private key in your outputs."
  type = string
  default = ""
}
