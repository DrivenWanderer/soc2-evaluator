namespace Soc2Evaluator.Core.Services;

public interface IEnvironmentProvider
{
    string? GetEnvironmentVariable(string variableName);
}

public class SystemEnvironmentProvider : IEnvironmentProvider
{
    public string? GetEnvironmentVariable(string variableName)
    {
        return Environment.GetEnvironmentVariable(variableName);
    }
}