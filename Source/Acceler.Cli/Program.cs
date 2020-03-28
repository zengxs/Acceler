using System;
using CommandLine;

namespace Acceler.Cli
{
    class Program
    {
        static int Main(string[] args)
        {
            return CommandLine.Parser.Default.ParseArguments<SniOptions>(args)
                .MapResult(
                    (SniOptions options) => options.RunAndReturnExitCode(),
                    errors => 1);
        }
    }
}
