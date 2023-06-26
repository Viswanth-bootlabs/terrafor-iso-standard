resource "aws_iam_role" "iam_role" {
  name = "${var.clustername}${var.iam_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "role_policy" {
  name = "${var.clustername}${var.iam_policy_name}"
  role = aws_iam_role.iam_role.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "iam:*",
          "s3:*",
          "route53:*",
          "ec2:*",
          "elasticloadbalancing:*",
          "autoscaling:*"
        ],
        "Resource" : "*"
      }
    ]
  })
}



resource "aws_vpc" "my_vpc" {
  cidr_block = var.vpc_cidir

  tags = {
    Name = "${var.clustername}${var.vpc_name}"
  }
}
resource "aws_route53_zone" "private_zone" {
  name = "${var.clustername}${var.roure53_name}"
  vpc {
    vpc_id     = aws_vpc.my_vpc.id
    vpc_region = var.region
  }
}

resource "aws_subnet" "second_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.subnet2_cidir
  availability_zone = var.subnet_zone

  tags = {
    Name = "${var.clustername}${var.subnet2_cidir}"
  }
}
resource "aws_internet_gateway" "chaos-internet-gateway" {
  vpc_id = aws_vpc.my_vpc.id
  tags = {
    Name = "${var.clustername}${var.Ig_name}"
  }
}
resource "aws_route_table" "chaos-rout-table" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = var.cidr_block
    gateway_id = aws_internet_gateway.chaos-internet-gateway.id
  }

  tags = {
    Name = "${var.clustername}${var.route_tabme_name}"
  }
}
resource "aws_route_table_association" "chaos-association" {
  subnet_id      = aws_subnet.second_subnet.id
  route_table_id = aws_route_table.chaos-rout-table.id
}

resource "aws_security_group" "security_group" {
  name   = "${var.clustername}${var.security_group_name}"
  vpc_id = aws_vpc.my_vpc.id

  ingress {
    description = var.ingress_discription
    from_port   = var.form_port
    to_port     = var.to_port
    protocol    = var.protocol
    cidr_blocks = var.sg_cidr

  }
  ingress {
    description = var.ingress_discription
    from_port   = var.port_443
    to_port     = var.port_443
    protocol    = var.protocol
    cidr_blocks = var.sg_cidr

  }
  ingress {
    description = var.ingress_discription
    from_port   = var.port_80
    to_port     = var.port_80
    protocol    = var.protocol
    cidr_blocks = [aws_vpc.my_vpc.cidr_block]

  }

  ingress {
    description = var.ingress_discription
    from_port   = var.port_from1
    to_port     = var.port_to1
    protocol    = var.protocol
    cidr_blocks = [aws_vpc.my_vpc.cidr_block]

  }
  ingress {
    description = var.ingress_discription
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.nat_ip

  }
  egress {
    from_port   = var.all_port
    to_port     = var.all_port
    protocol    = var.all_protocol
    cidr_blocks = var.sg_cidr

  }

}


data "aws_ami" "ubuntu" {

  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["${data.aws_caller_identity.current.account_id}"]
}
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.clustername}${var.ec2_profile_name}"
  role = aws_iam_role.iam_role.name
}
resource "aws_instance" "web-server" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  associate_public_ip_address = var.associate_public_ip_address
  key_name                    = aws_key_pair.generated_key.key_name
  subnet_id                   = aws_subnet.second_subnet.id
  vpc_security_group_ids      = [aws_security_group.security_group.id]
  monitoring                  = var.monitoring
  ebs_optimized               = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  metadata_options {
    http_endpoint               = "disabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }
  user_data = <<-EOL
    #!/bin/bash -xe
    sudo su 
    mkdir testing
    curl -Lo kops https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64
    chmod +x ./kops
    mv ./kops /usr/local/bin/
    curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
    sudo apt-get update
    snap install aws-cli --classic

  EOL
  root_block_device {
    volume_size           = var.volume_size
    encrypted             = true
    delete_on_termination = var.delete_on_termination
  }

  tags = {
    Name = "${var.clustername}${var.ec2_name}"
  }
  depends_on = [
    aws_subnet.second_subnet
  ]
}
resource "null_resource" "cluster" {
  connection {
    type        = "ssh"
    host        = aws_instance.web-server.public_ip
    user        = "ubuntu"
    private_key = tls_private_key.private_key.private_key_pem
  }

  provisioner "file" {
    source      = "./kops-cluster.sh"
    destination = "/home/ubuntu/kops-cluster.sh"
  }
  provisioner "file" {
    source      = "./Deployment"
    destination = "/home/ubuntu/Deployment"
  }
  provisioner "remote-exec" {
    inline = [
      "export zone1='ap-southeast-2a'",
      "export bucket='bucket-watermelon-27'",
      "export clustername='demo'",
      "export node_count=2",
      "echo $bucket",
      "chmod +x kops-cluster.sh",
      "./kops-cluster.sh ",
      "kubectl apply -f Deployment"

    ]
  }
  depends_on = [
    aws_instance.web-server
  ]
}

resource "tls_private_key" "private_key" {
  algorithm = var.ec2_algorithm
  rsa_bits  = var.ec2_rsa_bits
}

resource "aws_key_pair" "generated_key" {
  key_name   = "${var.clustername}${var.key_name}"
  public_key = tls_private_key.private_key.public_key_openssh

  provisioner "local-exec" {
    command = "echo '${tls_private_key.private_key.private_key_pem}' > ./chaos-key.pem"
  }
}


resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.clustername}${var.dashboard_name}"

  dashboard_body = <<EOF
{ 
    "widgets": [
        {
            "type": "metric",
            "x": 0,
            "y": 0,
            "width": 9,
            "height": 6,
            "properties": {
                "view": "bar",
                "stacked": false,
                "metrics": [
                    [ "AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", "Momo-Test-ASG1" ],
                    [ ".", "GroupMaxSize", ".", "." ],
                    [ ".", "GroupTotalCapacity", ".", "." ],
                    [ ".", "GroupTotalInstances", ".", "." ],
                    [ ".", "GroupInServiceInstances", ".", "." ]
                ],
                "region": "${var.region}",
                "title": "ASG1 statistics"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 0,
            "width": 9,
            "height": 6,
            "properties": {
                "view": "bar",
                "stacked": false,
                "metrics": [
                 [
                 "AWS/EC2",
                 "CPUUtilization",
                 "InstanceId",
                 "${aws_instance.web-server.id}"
                 ]
                ],
                "region": "${var.region}",
                "period": 300,
                "title": "ASG2 statistics"
            }
        },
        {
            "type": "explorer",
            "x": 0,
            "y": 6,
            "width": 24,
            "height": 15,
            "properties": {
                "metrics": [
                    {
                        "metricName": "CPUUtilization",
                        "resourceType": "AWS::EC2::Instance",
                        "stat": "Average"
                    },
                    {
                        "metricName": "NetworkIn",
                        "resourceType": "AWS::EC2::Instance",
                        "stat": "Average"
                    },
                    {
                        "metricName": "DiskReadOps",
                        "resourceType": "AWS::EC2::Instance",
                        "stat": "Average"
                    },
                    {
                        "metricName": "DiskWriteOps",
                        "resourceType": "AWS::EC2::Instance",
                        "stat": "Average"
                    },
                    {
                        "metricName": "NetworkOut",
                        "resourceType": "AWS::EC2::Instance",
                        "stat": "Average"
                    }
                ],
                "aggregateBy": {
                    "key": "*",
                    "func": "AVG"
                },
                "labels": [
                    {
                        "key": "aws:autoscaling:groupName",
                        "value": "Momo-Test-ASG1"
                    },
                    {
                        "key": "aws:autoscaling:groupName",
                        "value": "Momo-Test-ASG2"
                    }
                ],
                "widgetOptions": {
                    "legend": {
                        "position": "bottom"
                    },
                    "view": "timeSeries",
                    "stacked": false,
                    "rowsPerPage": 40,
                    "widgetsPerRow": 3
                },
                "period": 300,
                "splitBy": "",
                "title": "Average ASG1 and ASG2"
            }
        }
        
    ]
}
EOF
  depends_on = [
    aws_instance.web-server
  ]
}

resource "aws_s3_bucket" "storelogs" {
  bucket        = "${var.clustername}${var.log_bucket}"
  force_destroy = var.force_destroy
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "logging-bucket"
    target_prefix = "access-logs/"
  }
}

data "aws_iam_policy_document" "default" {
  statement {
    sid    = "AWSCloudTrailCreateLogStream2014110"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.storelogs.bucket}",
    ]
  }

  statement {
    sid    = "AWSCloudTrailPutLogEvents20141101"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.storelogs.bucket}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "CloudTrailS3Bucket" {
  bucket     = aws_s3_bucket.storelogs.id
  depends_on = [aws_s3_bucket.storelogs]
  policy     = data.aws_iam_policy_document.default.json
}

resource "aws_kms_key" "Key_store_log" {
  description             = var.kms_key_discriptyon
  deletion_window_in_days = var.KMS_deletion_window_in_days
  enable_key_rotation     = var.KMS_enable_key_rotation
  tags = {
    Name = "${var.clustername}${var.Kms_key_name}"
  }
}

resource "aws_cloudtrail" "default" {
  name                          = "${var.clustername}${var.cloudtrail_name}"
  enable_logging                = var.enable_logging
  s3_bucket_name                = aws_s3_bucket.storelogs.bucket
  enable_log_file_validation    = var.enable_log_file_validation
  is_multi_region_trail         = var.is_multi_region_trail
  include_global_service_events = var.include_global_service_events
  s3_key_prefix                 = var.s3_key_prefix
  kms_key_id                    = aws_kms_key.Key_store_log.arn
  depends_on = [
    aws_s3_bucket_policy.CloudTrailS3Bucket,
    null_resource.cluster
  ]
}

data "aws_vpc" "my_vpc" {
  filter {
    name   = "state"
    values = ["available"]
  }
  filter {
    name   = "Name"
    values = ["${var.clustername}-cluster.k8s.local"]
  }

}

resource "aws_flow_log" "example" {
  log_destination      = aws_s3_bucket.storelogs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = data.aws_vpc.my_vpc.id
  destination_options {
    per_hour_partition = true
  }
}
data "aws_caller_identity" "current" {

}

resource "aws_inspector2_enabler" "test" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = var.inspector_resource_types
  depends_on = [
    null_resource.cluster
  ]
}



resource "aws_guardduty_detector" "MyDetector" {
  enable                       = var.guardduty_enable
  finding_publishing_frequency = var.finding_publishing_frequency
  datasources {
    s3_logs {
      enable = var.guardduty_enable
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.guardduty_enable
        }
      }
    }
  }
  depends_on = [
    null_resource.cluster
  ]
}

resource "aws_wafv2_web_acl" "example" {
  name     = "${var.clustername}${var.waf_name}"
  scope    = var.waf_scope
  provider = aws.east
  default_action {
    allow {}
  }

  rule {
    name     = var.waf_rule_name
    priority = var.waf_rule_priority

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_limit
        aggregate_key_type = var.waf_aggregate_key_type

        scope_down_statement {
          geo_match_statement {
            country_codes = var.waf_rule_country_codes
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = var.visibility_config
      metric_name                = var.waf_visibility_config
      sampled_requests_enabled   = var.visibility_config
    }
  }

  tags = {
    Name = var.waf_visibility_config
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.visibility_config
    metric_name                = var.waf_visibility_config
    sampled_requests_enabled   = var.visibility_config
  }
  depends_on = [
    null_resource.cluster
  ]
}

resource "aws_securityhub_account" "example" {
  depends_on = [
    null_resource.cluster
  ]
}

