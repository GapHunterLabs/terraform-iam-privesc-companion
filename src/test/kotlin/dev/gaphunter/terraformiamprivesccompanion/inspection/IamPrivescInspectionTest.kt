package dev.gaphunter.terraformiamprivesccompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

/**
 * Exercises the real cross-file graph: the admin-granting attachment
 * lives in a SEPARATE file from the role that trusts (and thus can
 * escalate through) the target role -- proving [ProjectIamGraphBuilder]
 * actually aggregates across every `.tf` file in the project, not just
 * the one file being highlighted.
 */
class IamPrivescInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(IamPrivescInspection::class.java)
    }

    fun `test a role that can assume an admin role in another file is flagged`() {
        myFixture.addFileToProject(
            "admin.tf",
            """
            resource "aws_iam_role_policy_attachment" "target_admin" {
              role       = aws_iam_role.target_role.name
              policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            }
            """.trimIndent(),
        )
        myFixture.configureByText(
            "main.tf",
            """
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
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("low_priv -> target_role") == true })
        // target_role is itself admin-equivalent (via the attachment) -- never flagged as escalating TO itself.
        assertTrue(highlights.none { it.description?.contains("Role 'target_role'") == true })
    }

    fun `test a role with no path to an admin role is not flagged`() {
        myFixture.configureByText(
            "isolated.tf",
            """
            resource "aws_iam_role" "lonely" {
              name = "lonely"
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("escalate to an admin-equivalent role") == true })
    }

    fun `test a two-hop escalation chain across three files is followed`() {
        myFixture.addFileToProject(
            "middle.tf",
            """
            resource "aws_iam_role" "middle_role" {
              name = "middle-role"
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
            """.trimIndent(),
        )
        myFixture.addFileToProject(
            "admin_attach.tf",
            """
            resource "aws_iam_role" "admin_role" {
              name = "admin-role"
              assume_role_policy = jsonencode({
                Statement = [
                  {
                    Effect = "Allow"
                    Principal = {
                      AWS = aws_iam_role.middle_role.arn
                    }
                    Action = "sts:AssumeRole"
                  }
                ]
              })
            }
            resource "aws_iam_role_policy_attachment" "admin_attach" {
              role       = aws_iam_role.admin_role.name
              policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            }
            """.trimIndent(),
        )
        myFixture.configureByText(
            "low.tf",
            """
            resource "aws_iam_role" "low_priv" {
              name = "low-priv"
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("low_priv -> middle_role -> admin_role") == true })
    }

    fun `test a non-tf file is never scanned`() {
        myFixture.configureByText(
            "Notes.java",
            "String x = \"resource aws_iam_role\";",
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("AssumeRole trust chain") == true })
    }
}
