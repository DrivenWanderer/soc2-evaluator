namespace Soc2Evaluator.Rules;

public static class SourceFileHelper
{
    private static readonly HashSet<string> ExcludedDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin", "obj", ".git", ".vs", "node_modules", ".gemini", ".idea", "reports", "TestResults"
    };

    public static IEnumerable<string> FindSourceFiles(string rootPath, string extension = "*.cs")
    {
        if (File.Exists(rootPath))
        {
            if (rootPath.EndsWith(extension.TrimStart('*'), StringComparison.OrdinalIgnoreCase))
            {
                yield return rootPath;
            }
            yield break;
        }

        if (!Directory.Exists(rootPath))
        {
            yield break;
        }

        var dirInfo = new DirectoryInfo(rootPath);
        foreach (var file in EnumerateFilesSafe(dirInfo, extension))
        {
            yield return file.FullName;
        }
    }

    private static IEnumerable<FileInfo> EnumerateFilesSafe(DirectoryInfo dir, string pattern)
    {
        FileInfo[] files;
        try
        {
            files = dir.GetFiles(pattern);
        }
        catch
        {
            yield break;
        }

        foreach (var file in files)
        {
            yield return file;
        }

        DirectoryInfo[] subDirs;
        try
        {
            subDirs = dir.GetDirectories();
        }
        catch
        {
            yield break;
        }

        foreach (var sub in subDirs)
        {
            if (!ExcludedDirs.Contains(sub.Name))
            {
                foreach (var f in EnumerateFilesSafe(sub, pattern))
                {
                    yield return f;
                }
            }
        }
    }
}