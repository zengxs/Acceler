using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Acceler.Proxy
{
    public class SniProxy : IProxy
    {
        public int Port { get; private set; }

        private string _proxyHost = null;
        private int? _proxyPort = null;

        public SniProxy(string proxyHost = null, int? proxyPort = null)
        {
            _proxyHost = proxyHost;
            _proxyPort = proxyPort;
        }

        public async Task StartAsync(int port = 8443)
        {
            Port = port;
            var server = new TcpListener(IPAddress.Any, 8443);
            Console.WriteLine("SNI Proxy listening at 127.0.0.1:8443...");
            server.Start();

            while (true)
            {
                var client = await server.AcceptTcpClientAsync();
                try
                {
                    HandleConnection(client);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.ToString());
                }
            }
        }

        private async void HandleConnection(TcpClient client)
        {
            var stream = client.GetStream();
            var buffer = new byte[5];

            // Parse TLS 1.2 Client Hello
            // Ref: https://tls.ulfheim.net

            // Read Record Header
            //  handshake record: 0x16 (1 byte)
            //  protocol version is 3.1 (also known as TLS 1.0): 0x03 0x01 (2 bytes)
            //  handshake message length: 0x00 0xa5 (2 bytes)
            await stream.ReadAsync(buffer, 0, 5);
            // Accept TLS_v1 request only.
            if (!buffer.Take(3).SequenceEqual(new byte[] {0x16, 0x03, 0x01}))
            {
                Console.WriteLine("Not valid TLSv1 client hello");
                var alertMsg = new byte[]
                {
                    0x15, // Content Type: Alert
                    0x03, 0x01, // Protocol Version: TLS v1 (includes 1.0, 1.1, 1.2, 1.3...)
                    0x00, 0x02, // Follows Length: 2
                    0x02, // Alert Message Level: Fatal
                    0x28, // Alert Message Description: Handshake Failure
                };
                await stream.WriteAsync(alertMsg, 0, alertMsg.Length);
                stream.Close();
                client.Close();
                return;
            }

            int clientHelloLength = BitConverter.ToUInt16(buffer.Skip(3).Take(2).Reverse().ToArray(), 0);
            Console.WriteLine($"Client Hello Length = {clientHelloLength + 5}");

            Array.Resize(ref buffer, 5 + clientHelloLength);
            await stream.ReadAsync(buffer, 5, clientHelloLength);

            Console.WriteLine(BitConverter.ToString(buffer));

            var host = await ParseSniHost(new MemoryStream(buffer));

            await DialToRemote(stream, host, buffer);

            stream.Close();
            client.Close();
        }

        private async Task DialToRemote(NetworkStream clientStream, string remoteHost, byte[] clientHello)
        {
            var remote = new TcpClient();
            NetworkStream remoteStream;
            if (_proxyHost == null || _proxyPort == null)
            {
                var remoteIpAddresses = await Dns.GetHostAddressesAsync(remoteHost); // 直接连接
                await remote.ConnectAsync(remoteIpAddresses[0], 443);
                remoteStream = remote.GetStream();
            }
            else
            {
                // 使用 HTTP 代理
                var httpProxyIpAddresses = await Dns.GetHostAddressesAsync(_proxyHost);
                await remote.ConnectAsync(httpProxyIpAddresses[0], _proxyPort.Value);
                remoteStream = remote.GetStream();

                var sb = new StringBuilder();
                sb.Append($"CONNECT {remoteHost}:443 HTTP/1.0\r\n");
                sb.AppendFormat("User-Agent: Acceler/{0}\r\n", Assembly.GetExecutingAssembly().GetName().Version);
                sb.Append("\r\n");

                var buf = Encoding.ASCII.GetBytes(sb.ToString());
                await remoteStream.WriteAsync(buf, 0, buf.Length);
                var receive = await ReceiveUntil(remoteStream, Encoding.ASCII.GetBytes("\r\n\r\n"));
                Console.WriteLine(Encoding.Default.GetString(receive));
            }

            await remoteStream.WriteAsync(clientHello, 0, clientHello.Length);
            remoteStream.CopyToAsync(clientStream);
            await clientStream.CopyToAsync(remoteStream);

            remoteStream.Close();
            remote.Close();
        }

        private async Task<byte[]> ReceiveUntil(Stream stream, byte[] terminal)
        {
            var buffer = new byte[terminal.Length];

            await stream.ReadAsync(buffer, 0, buffer.Length);
            while (!buffer.Reverse().Take(terminal.Length).Reverse().SequenceEqual(terminal))
            {
                var offset = buffer.Length;
                Array.Resize(ref buffer, buffer.Length + 1);
                await stream.ReadAsync(buffer, offset, 1);
            }

            return buffer;
        }

        private async Task<string> ParseSniHost(MemoryStream clientHello)
        {
            var buffer = new byte[4];
            clientHello.Seek(5 + 4 + 2 + 32, SeekOrigin.Begin);

            // Session ID
            await clientHello.ReadAsync(buffer, 0, 1);
            clientHello.Seek(buffer[0], SeekOrigin.Current);

            // Cipher Suites
            await clientHello.ReadAsync(buffer, 0, 2);
            var csLength = BitConverter.ToUInt16(buffer.Take(2).Reverse().ToArray(), 0);
            clientHello.Seek(csLength, SeekOrigin.Current);

            // Compression Methods
            await clientHello.ReadAsync(buffer, 0, 1);
            clientHello.Seek(buffer[0], SeekOrigin.Current);

            // Extensions
            await clientHello.ReadAsync(buffer, 0, 2);
            int extLength = BitConverter.ToUInt16(buffer.Take(2).Reverse().ToArray(), 0);

            if (extLength <= 0)
            {
                return null;
            }

            // Parse extensions
            while (extLength > 0)
            {
                extLength -= await clientHello.ReadAsync(buffer, 0, 2);
                int extType = BitConverter.ToUInt16(buffer.Take(2).Reverse().ToArray(), 0);

                extLength -= await clientHello.ReadAsync(buffer, 0, 2);
                int extFollowLength = BitConverter.ToUInt16(buffer.Take(2).Reverse().ToArray(), 0);

                if (extType == 0)
                {
                    var data = new byte[extFollowLength];
                    await clientHello.ReadAsync(data, 0, extFollowLength);

                    int hostLength = BitConverter.ToUInt16(data.Skip(3).Take(2).Reverse().ToArray(), 0);
                    return Encoding.Default.GetString(data.Skip(5).Take(hostLength).ToArray());
                }

                clientHello.Seek(extFollowLength, SeekOrigin.Current);
                extLength -= extFollowLength;
            }

            return null;
        }
    }
}
