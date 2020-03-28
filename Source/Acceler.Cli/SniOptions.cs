using System;
using Acceler.Proxy;
using CommandLine;

namespace Acceler.Cli
{
    [Verb("sni")]
    internal class SniOptions : IOptions
    {
        [Option("uri", Default = "sni+http://127.0.0.1:8443", HelpText = "Port binding for TLS SNI proxy server.")]
        public string Uri { get; set; }

        public int RunAndReturnExitCode()
        {
            var server = new SniProxy();
            server.StartAsync().GetAwaiter().GetResult();
            return 0;
        }
    }
}
