# Bad Terraform configuration with multiple security issues

# Issue 1: S3 bucket with public access
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # BAD: Public access enabled
}

# Issue 2: Security group with overly permissive ingress
resource "aws_security_group" "bad_sg" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD: Open to the world
  }
}

# Issue 3: RDS instance without encryption
resource "aws_db_instance" "bad_db" {
  identifier           = "mydb"
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "admin"
  password             = "password123"  # BAD: Hardcoded password
  storage_encrypted    = false          # BAD: No encryption
  publicly_accessible  = true           # BAD: Publicly accessible
  skip_final_snapshot  = true
}

# Issue 4: EC2 instance with public IP and no key
resource "aws_instance" "bad_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  associate_public_ip_address = true  # BAD: Public IP
  
  metadata_options {
    http_tokens = "optional"  # BAD: Should require IMDSv2
  }
}

# Issue 5: IAM policy with wildcard permissions
resource "aws_iam_policy" "bad_policy" {
  name        = "admin_policy"
  description = "Admin policy with full access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "*"        # BAD: Wildcard permissions
        Effect = "Allow"
        Resource = "*"      # BAD: All resources
      },
    ]
  })
}

# Issue 6: CloudWatch logs without encryption
resource "aws_cloudwatch_log_group" "bad_logs" {
  name = "/aws/lambda/my-function"
  # BAD: Missing kms_key_id for encryption
}

# Issue 7: EBS volume without encryption
resource "aws_ebs_volume" "bad_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false  # BAD: No encryption
}
