using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Soc2Evaluator.Cli;

var services = new ServiceCollection();
services.AddLogging(builder =>
{
    builder.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.TimestampFormat = "HH:mm:ss ";
    });
    builder.SetMinimumLevel(LogLevel.Information);
});

var serviceProvider = services.BuildServiceProvider();
var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

var rootCommand = CommandLineBuilder.BuildRootCommand(async (scanOptions, cancellationToken) =>
{
    logger.LogInformation("Starting SOC 2 evaluation for target: {Target}", scanOptions.Target);
    logger.LogInformation("Evidence and reports will be saved to: {OutputPath}", scanOptions.OutputPath);
    await Task.CompletedTask;
    return 0;
});

var parseResult = rootCommand.Parse(args);
return await parseResult.InvokeAsync();