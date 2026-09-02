package dev.gaphunter.terraformiamprivesccompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import dev.gaphunter.terraformiamprivesccompanion.detect.ProjectIamGraphBuilder
import dev.gaphunter.terraformiamprivesccompanion.detect.TerraformIamParser
import dev.gaphunter.terraformiamprivesccompanion.model.EscalationPath
import dev.gaphunter.terraformiamprivesccompanion.review.ReviewPrompt

/**
 * Flags a `resource "aws_iam_role"` that can reach an
 * admin-equivalent role through a real AssumeRole trust chain
 * ([ProjectIamGraphBuilder]'s whole-project graph, BFS with cycle
 * protection -- never a fixed-depth heuristic) -- a genuine
 * multi-hop privilege-escalation path (CWE-269), not just an isolated
 * wildcard statement (`terraform-iam-wildcard-companion`'s own,
 * narrower scope).
 *
 * Re-parses only the CURRENT file via [TerraformIamParser] to get this
 * file's own role declarations + local offsets (cheap, and the
 * reliable way to anchor a warning in THIS file even if the
 * project-wide graph's `roleDeclarations` map happened to keep a
 * different file's declaration for the same role name -- see that
 * map's `putIfAbsent` note); the actual escalation-path computation
 * comes from the real, cached, whole-project graph.
 */
class IamPrivescInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
        private val TF_FILE_NAME = Regex("""^[^.]+\.tf$""", RegexOption.IGNORE_CASE)
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val virtualFile = file.virtualFile ?: return null
        if (!TF_FILE_NAME.matches(virtualFile.name)) return null

        val text = file.text
        if (text.length > MAX_FILE_LENGTH) return null

        val localRoles = TerraformIamParser.parseFile(text, virtualFile.path).roles
        if (localRoles.isEmpty()) return null

        val graph = ProjectIamGraphBuilder.graphFor(file.project)
        val document = file.viewProvider.document ?: return null
        val problems = mutableListOf<ProblemDescriptor>()

        for (role in localRoles) {
            val escalationPath = graph.findEscalationPath(role.name) ?: continue

            val lineNumber = document.getLineNumber(role.declarationOffset)
            if (lineNumber !in 0 until document.lineCount) continue
            val lineStartOffset = document.getLineStartOffset(lineNumber)
            val lineEndOffset = document.getLineEndOffset(lineNumber)
            val anchor = leafElementAt(file, lineStartOffset) ?: continue
            val anchorStart = anchor.textRange.startOffset
            val relativeRange = TextRange(
                (lineStartOffset - anchorStart).coerceAtLeast(0),
                (lineEndOffset - anchorStart).coerceAtMost(anchor.textLength),
            )
            if (relativeRange.startOffset >= relativeRange.endOffset) continue

            problems += manager.createProblemDescriptor(
                anchor,
                relativeRange,
                messageFor(role.name, escalationPath),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                isOnTheFly,
            )
            ReviewPrompt.recordHit(file.project, "${virtualFile.path}:${role.name}")
        }

        return if (problems.isEmpty()) null else problems.toTypedArray()
    }

    private fun messageFor(roleName: String, path: EscalationPath): String =
        "Role '$roleName' can escalate to an admin-equivalent role through a real AssumeRole trust chain: " +
            "${path.describe()} -- a genuine multi-hop privilege-escalation path (CWE-269)"

    private fun leafElementAt(file: PsiFile, startOffset: Int): PsiElement? {
        if (startOffset < 0 || startOffset >= file.textLength) return null
        var element = file.findElementAt(startOffset) ?: return file
        while (element.firstChild != null) {
            element = element.firstChild
        }
        return element
    }
}
