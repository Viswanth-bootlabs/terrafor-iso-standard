terraform {
  required_version = ">=1.1.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.67.0"
    }
  }

  # backend "s3" {
  # }
}

# provider "aws" {
#   region = "ap-sutheast-2"

# }
provider "aws" {
  alias  = "east"
  region = "us-east-1"
}