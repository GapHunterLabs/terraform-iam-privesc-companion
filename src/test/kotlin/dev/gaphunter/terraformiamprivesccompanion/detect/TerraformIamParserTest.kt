package dev.gaphunter.terraformiamprivesccompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TerraformIamParserTest {

    @Test
    fun `role declaration is found`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role" "app_role" {
              name = "app-role"
            }
            """.trimIndent(),
            "main.tf",
        )
        assertEquals(1, facts.roles.size)
        assertEquals("app_role", facts.roles[0].name)
    }

    @Test
    fun `assume_role_policy trusting another role via direct reference produces a trust edge`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role" "target_role" {
              assume_role_policy = jsonencode({
                Version = "2012-10-17"
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
            """.trimIndent(),
            "main.tf",
        )
        assertEquals(1, facts.trustEdges.size)
        assertEquals("low_priv", facts.trustEdges[0].fromRole)
        assertEquals("target_role", facts.trustEdges[0].toRole)
    }

    @Test
    fun `assume_role_policy without sts AssumeRole action produces no trust edge`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role" "target_role" {
              assume_role_policy = jsonencode({
                Statement = [
                  {
                    Effect = "Allow"
                    Principal = {
                      AWS = aws_iam_role.low_priv.arn
                    }
                    Action = "sts:TagSession"
                  }
                ]
              })
            }
            """.trimIndent(),
            "main.tf",
        )
        assertTrue(facts.trustEdges.isEmpty())
    }

    @Test
    fun `a full wildcard policy definition is admin-equivalent`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_policy" "danger" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
            """.trimIndent(),
            "main.tf",
        )
        assertEquals(1, facts.policyDefinitions.size)
        assertTrue(facts.policyDefinitions[0].isAdminEquivalent)
    }

    @Test
    fun `a scoped policy definition is not admin-equivalent`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_policy" "scoped" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "s3:GetObject"
                    Resource = "arn:aws:s3:::my-bucket/*"
                  }
                ]
              })
            }
            """.trimIndent(),
            "main.tf",
        )
        assertFalse(facts.policyDefinitions[0].isAdminEquivalent)
    }

    @Test
    fun `attachment with literal AdministratorAccess ARN is recognized`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role_policy_attachment" "attach" {
              role       = aws_iam_role.target_role.name
              policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            }
            """.trimIndent(),
            "main.tf",
        )
        assertEquals(1, facts.attachments.size)
        assertEquals("target_role", facts.attachments[0].roleName)
        assertEquals("arn:aws:iam::aws:policy/AdministratorAccess", facts.attachments[0].literalPolicyArn)
    }

    @Test
    fun `attachment referencing an aws_iam_policy resource is recognized`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role_policy_attachment" "attach" {
              role       = aws_iam_role.target_role.id
              policy_arn = aws_iam_policy.danger.arn
            }
            """.trimIndent(),
            "main.tf",
        )
        assertEquals("target_role", facts.attachments[0].roleName)
        assertEquals("danger", facts.attachments[0].referencedPolicyResourceName)
    }

    @Test
    fun `inline policy with full wildcard is admin-equivalent`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role_policy" "inline" {
              name = "inline"
              role = aws_iam_role.target_role.id
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
            """.trimIndent(),
            "main.tf",
        )
        assertEquals(1, facts.inlinePolicies.size)
        assertEquals("target_role", facts.inlinePolicies[0].roleName)
        assertTrue(facts.inlinePolicies[0].isAdminEquivalent)
    }

    @Test
    fun `a literal cross-account ARN principal produces no trust edge`() {
        val facts = TerraformIamParser.parseFile(
            """
            resource "aws_iam_role" "target_role" {
              assume_role_policy = jsonencode({
                Statement = [
                  {
                    Effect = "Allow"
                    Principal = {
                      AWS = "arn:aws:iam::999999999999:role/external-role"
                    }
                    Action = "sts:AssumeRole"
                  }
                ]
              })
            }
            """.trimIndent(),
            "main.tf",
        )
        assertTrue(facts.trustEdges.isEmpty())
    }
}
