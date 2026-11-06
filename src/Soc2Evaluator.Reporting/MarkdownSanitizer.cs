using System.Net;
using System.Text.RegularExpressions;

namespace Soc2Evaluator.Reporting;

public static class MarkdownSanitizer
{
    public static string EscapeTableCell(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        // Escape pipes and angle brackets to prevent table formatting breaks and HTML injection
        return text
            .Replace("\r\n", " ")
            .Replace("\n", " ")
            .Replace("|", "\\|")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;");
    }

    public static string EscapeMarkdown(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        // Escape HTML tags to prevent raw HTML injection into rendered markdown
        return text
            .Replace("<", "&lt;")
            .Replace(">", "&gt;");
    }
}