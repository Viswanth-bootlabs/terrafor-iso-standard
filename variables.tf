variable "iam_name" {
  description = "name of the iam name"
  type        = string
  default     = "-iam-cluster.k8s.local"

}
variable "node_count" {
  description = "number of nodes to be create"
  type        = number
  default     = "1"

}
variable "zone" {
  description = "name of the iam name"
  type        = string
  default     = " "

}
variable "iam_policy_name" {
  description = "name of the iam name"
  type        = string
  default     = "-policy-cluster.k8s.local"
}
variable "clustername" {
  description = "iam policy name"
  type        = string
  default     = "chaos_cluster"

}

variable "vpc_name" {
  description = "name of the vpc"
  type        = string
  default     = "-vpc-cluster.k8s.local"

}

variable "vpc_cidir" {
  description = "cidir block for vpc"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet1_cidir" {
  description = "cidir block for subnet"
  type        = string
  default     = "10.0.1.0/24"
}
variable "subnet_zone" {
  description = "availability zone for the subnets"
  type        = string
  default     = "ap-southeast-2a"
}
variable "subnet2_cidir" {
  description = "subnet2 cidir block"
  type        = string
  default     = "10.0.2.0/24"
}
variable "subnet2_name" {
  description = "name of the subnet2"
  type        = string
  default     = "-subnet-cluster.k8s.local"
}
variable "security_group_name" {
  description = "name of the security group"
  type        = string
  default     = "-sg-cluster.k8s.local"
}

variable "form_port" {
  description = "Enter the from port"
  type        = number
  default     = 22
}

variable "to_port" {
  description = "Enter the to port"
  type        = number
  default     = 22
}

variable "protocol" {
  description = "Enter the to protocol"
  type        = string
  default     = "tcp"
}

variable "bucket_name" {
  description = "Enter the bucket name"
  type        = string
  default     = ""
}

variable "acl_s3" {
  description = "Enter the bucket acl permission"
  type        = string
  default     = "private"
}

variable "instance_type" {
  description = "The type of instance to start"
  type        = string
  default     = "t3.nano"

}

variable "volume_size" {
  description = "Whether to create an instance Size of the root volume in gigabytes"
  type        = number
  default     = 8
}

variable "ec2_name" {
  description = "Name to be used on EC2 instance created"
  type        = string
  default     = "-ec2-cluster.k8s.localn"
}

variable "key_name" {
  description = "Key name of the Key Pair to use for the instance; which can be managed using the aws_key_pair resource"
  type        = string
  default     = "-key-name-cluster.k8s.local"
}

variable "region" {
  description = "AWS Region the instance is launched in"
  type        = string
  default     = "ap-southeast-2"
}

variable "ec2_algorithm" {
  description = "Algorithm for private key in ec2"
  type        = string
  default     = "RSA"
}

variable "ec2_rsa_bits" {
  description = "no of bits for rsa algorithm"
  type        = number
  default     = 4690
}

variable "Ig_name" {
  description = "Name of Ig."
  type        = string
  default     = "-ig-cluster.k8s.local"
}

variable "roure53_name" {
  description = "Name of the route53"
  type        = string
  default     = "-route53-cluster.k8s.local"
}
variable "route_tabme_name" {
  description = "Name of the route table"
  type        = string
  default     = "-routetable-cluster.k8s.local"
}

variable "ingress_discription" {
  description = "Ingress description"
  type        = string
  default     = "TLS from VPC"
}

variable "port_443" {
  description = "port 443"
  type        = number
  default     = 443
}
variable "port_80" {
  description = "port 80"
  type        = number
  default     = 80
}

variable "nat_ip" {
  description = "NAT ip"
  type        = list(string)
  default     = [""]
}
variable "port_from1" {
  description = "port 1024"
  type        = number
  default     = 1024
}
variable "port_to1" {
  description = "port 65535"
  type        = number
  default     = 65535
}
variable "all_port" {
  description = "port all"
  type        = number
  default     = 0
}
variable "all_protocol" {
  description = "all protocol"
  type        = string
  default     = "-1"
}
variable "cidr_block" {
  description = "roude cidr"
  type        = string
  default     = "0.0.0.0/0"
}
variable "ec2_profile_name" {
  description = "ec2_profile name"
  type        = string
  default     = "ec2-profile-cluster.k8s.local"
}
variable "associate_public_ip_address" {
  description = "Enable associate piblic ip"
  type        = bool
  default     = true
}
variable "monitoring" {
  description = "Monitor ec2 enable"
  type        = bool
  default     = true
}
variable "delete_on_termination" {
  description = "Monitor ec2 enable"
  type        = bool
  default     = false
}
variable "dashboard_name" {
  description = "cloud watch dashboard name"
  type        = string
  default     = "-cloudwatch-dashbord-cluster.k8s.local"
}
variable "log_bucket" {
  description = "Name of log bucket"
  type        = string
  default     = "-bucket-cluster.k8s.local"
}
variable "force_destroy" {
  description = "Enambel bucket force destroy"
  type        = bool
  default     = true
}
variable "Kms_key_name" {
  description = "Kms key name"
  type        = string
  default     = "-KMS-cluster.k8s.local"
}
variable "cloudtrail_name" {
  description = "Cloud trail  name"
  type        = string
  default     = "-cloudtrail-cluster.k8s.local"
}
variable "enable_logging" {
  description = "Cloud trail enable logging"
  type        = bool
  default     = true
}
variable "enable_log_file_validation" {
  description = "Cloud trail enable log file validation"
  type        = bool
  default     = true
}
variable "is_multi_region_trail" {
  description = "Cloud trail is multi region trail"
  type        = bool
  default     = true
}
variable "include_global_service_events" {
  description = "Cloud trail include global service events"
  type        = bool
  default     = true
}
variable "s3_key_prefix" {
  description = "Cloud trail s3 key prefix"
  type        = string
  default     = "cloudtrail"
}
variable "guardduty_enable" {
  description = "Guardduty detector enable"
  type        = bool
  default     = true
}
variable "finding_publishing_frequency" {
  description = "Guardduty detector finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
}
variable "waf_visibility_config" {
  description = "waf rule name"
  type        = string
  default     = "watermelon"
}
variable "visibility_config" {
  description = "waf visibility config enable"
  type        = bool
  default     = false
}
variable "waf_aggregate_key_type" {
  description = "waf aggregate key type"
  type        = string
  default     = "IP"
}
variable "waf_limit" {
  description = "waf IP limit"
  type        = number
  default     = 10000
}
variable "waf_rule_name" {
  description = "waf IP limit"
  type        = string
  default     = "rule_1"
}
variable "waf_rule_priority" {
  description = "waf IP limit"
  type        = number
  default     = 1
}
variable "waf_scope" {
  description = "waf scope"
  type        = string
  default     = "CLOUDFRONT"
}
variable "waf_name" {
  description = "waf scope"
  type        = string
  default     = "-waf-cluster.k8s.local"
}
variable "kms_key_discriptyon" {
  description = "KMS discription"
  type        = string
  default     = "KMS Key 1"
}
variable "KMS_deletion_window_in_days" {
  description = "KMS deletion window in days"
  type        = number
  default     = 30
}
variable "KMS_enable_key_rotation" {
  description = "KMS enable key rotation"
  type        = bool
  default     = true
}
variable "inspector_resource_types" {
  description = "Inspector resource typt"
  type        = list(string)
  default     = ["EC2"]
}
variable "waf_rule_country_codes" {
  description = "waf rule country codes"
  type        = list(string)
  default     = ["US", "NL"]
}
variable "sg_cidr" {
  description = "Ingress Egress cidr"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

