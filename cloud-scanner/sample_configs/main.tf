# =============================================================================
# sample_configs/main.tf
# INTENTIONALLY VULNERABLE — for demo/testing the Cloud Scanner only.
# DO NOT deploy this infrastructure.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ── S3: public ACL, no encryption, no versioning ──────────────────────────────

resource "aws_s3_bucket" "data_lake" {
  bucket = "my-company-data-lake"
  acl    = "public-read"          # TF001: public ACL

  tags = {
    Name        = "data-lake"
    Environment = "production"
  }
}

# Missing: aws_s3_bucket_server_side_encryption_configuration → TF002
# Missing: aws_s3_bucket_versioning → TF003

resource "aws_s3_bucket" "backups" {
  bucket = "my-company-backups-2024"
  acl    = "public-read-write"    # TF001: even worse — public write!
}


# ── Security Groups: wide open ────────────────────────────────────────────────

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Web server security group"
  vpc_id      = "vpc-12345678"

  # TF010: allow all inbound
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Bastion host"
  vpc_id      = "vpc-12345678"

  # TF011: SSH open to world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # TF012: RDP open to world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db_sg" {
  name        = "db-sg"
  description = "Database security group"
  vpc_id      = "vpc-12345678"

  # TF013: PostgreSQL open to world
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # TF014: MySQL open to world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # TF015: MongoDB open to world
  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # TF016: Redis open to world
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# ── IAM: wildcard permissions ─────────────────────────────────────────────────

resource "aws_iam_policy" "admin_policy" {
  name        = "AdminEverything"
  description = "Grants full admin access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"          # TF020: wildcard action
        Resource = "*"          # TF021: wildcard resource
      }
    ]
  })
}

resource "aws_iam_policy" "s3_wildcard" {
  name = "S3FullAccess"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"       # TF020: wildcard action on S3
        Resource = "*"
      }
    ]
  })
}


# ── RDS: public, no encryption, no backup ────────────────────────────────────

resource "aws_db_instance" "main_db" {
  identifier           = "production-db"
  engine               = "postgres"
  engine_version       = "14"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  db_name              = "appdb"
  username             = "admin"
  password             = "SuperSecret123!"   # hardcoded password → secrets scan

  publicly_accessible  = true               # TF030: public RDS
  storage_encrypted    = false              # TF031: no encryption
  backup_retention_period = 0              # TF032: no backups

  skip_final_snapshot  = true
}

resource "aws_db_instance" "analytics_db" {
  identifier        = "analytics-db"
  engine            = "mysql"
  instance_class    = "db.t3.small"
  allocated_storage = 50
  username          = "root"
  password          = "Mysql@Pass2024"      # hardcoded password

  publicly_accessible     = true           # TF030
  storage_encrypted       = false          # TF031
  backup_retention_period = 0             # TF032
}


# ── EC2: public IP, unencrypted EBS ──────────────────────────────────────────

resource "aws_instance" "web_server" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t3.medium"
  associate_public_ip_address = true        # TF040: public IP

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = false                     # TF041: EBS not encrypted
  }

  tags = {
    Name = "web-server"
  }
}

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  encrypted         = false                 # TF041: EBS not encrypted
}


# ── ElasticSearch open to world ───────────────────────────────────────────────

resource "aws_security_group" "es_sg" {
  name   = "elasticsearch-sg"
  vpc_id = "vpc-12345678"

  # TF017: Elasticsearch open to world
  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
