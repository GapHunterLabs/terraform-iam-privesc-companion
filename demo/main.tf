resource "aws_iam_role" "low_priv" {
  name = "low-priv"
}

resource "aws_iam_role" "target_role" {
  name = "target-role"
  assume_role_policy = jsonencode({
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.low_priv.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}