namespace Soc2Evaluator.Tests.TestHelpers;

public class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

    public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(_handler(request));
    }
}

public class MockEnvironmentProvider : Core.Services.IEnvironmentProvider
{
    private readonly Dictionary<string, string> _vars = new(StringComparer.OrdinalIgnoreCase);

    public MockEnvironmentProvider(Dictionary<string, string>? initialVars = null)
    {
        if (initialVars != null)
        {
            foreach (var (k, v) in initialVars)
            {
                _vars[k] = v;
            }
        }
    }

    public void Set(string key, string value) => _vars[key] = value;

    public string? GetEnvironmentVariable(string variableName)
    {
        return _vars.TryGetValue(variableName, out var val) ? val : null;
    }
}