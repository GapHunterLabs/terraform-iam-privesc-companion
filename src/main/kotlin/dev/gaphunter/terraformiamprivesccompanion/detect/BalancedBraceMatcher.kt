package dev.gaphunter.terraformiamprivesccompanion.detect

/**
 * Finds the index of the closing bracket that matches the opening
 * bracket at [openIndex] in [text] -- respects nested brackets of the
 * SAME type and skips over bracket characters inside a double-quoted
 * string literal. Handles a backslash-escaped quote inside the string
 * so it doesn't end the string early.
 *
 * Same utility as `terraform-iam-wildcard-companion`'s own copy --
 * each plugin in this catalog is a self-contained Gradle project with
 * no shared library dependency, so it's duplicated here rather than
 * referenced across repos.
 */
object BalancedBraceMatcher {

    fun findMatchingClose(text: String, openIndex: Int, openChar: Char, closeChar: Char): Int? {
        if (openIndex !in text.indices || text[openIndex] != openChar) return null

        var depth = 0
        var inString = false
        var i = openIndex
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                when (c) {
                    '\\' -> i++
                    '"' -> inString = false
                }
            } else {
                when (c) {
                    '"' -> inString = true
                    openChar -> depth++
                    closeChar -> {
                        depth--
                        if (depth == 0) return i
                    }
                }
            }
            i++
        }
        return null
    }
}
