resource "aws_iam_role_policy_attachment" "target_admin" {
  role       = aws_iam_role.target_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}