using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Diagnostics;

namespace xbLive_API
{
    public static class Utils
    {
        public static string BytesToHexString(byte[] Buffer)
        {
            try
            {
                string str = "";
                for (int i = 0; i < Buffer.Length; i++)
                {
                    str = str + Buffer[i].ToString("X2");
                }
                return str;
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
            }
            return "";
        }

        public static unsafe Array intToArray(uint num)
        {
            try
            {
                byte[] arr = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    byte* val = (byte*)&num;
                    arr[i] = val[i];
                }
                return arr;
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        public static UInt32 ReverseBytes(UInt32 value)
        {
            try
            {
                return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                       (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return 0;
            }
        }

        public static void RC4(ref byte[] Data, byte[] Key)
        {
            try
            {
                byte num;
                int num2;
                byte[] buffer = new byte[0x100];
                byte[] buffer2 = new byte[0x100];
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    buffer[num2] = (byte)num2;
                    buffer2[num2] = Key[num2 % Key.GetLength(0)];
                }
                int index = 0;
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    index = ((index + buffer[num2]) + buffer2[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                }
                num2 = index = 0;
                for (int i = 0; i < Data.GetLength(0); i++)
                {
                    num2 = (num2 + 1) % 0x100;
                    index = (index + buffer[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                    int num5 = (buffer[num2] + buffer[index]) % 0x100;
                    Data[i] = (byte)(Data[i] ^ buffer[num5]);
                }
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return;
            }
        }

        public static void RC4Size(ref byte[] Data, int inputOffset, byte[] Key, int totalSize)
        {
            try
            {
                byte num;
                int num2;
                byte[] buffer = new byte[0x100];
                byte[] buffer2 = new byte[0x100];
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    buffer[num2] = (byte)num2;
                    buffer2[num2] = Key[num2 % Key.GetLength(0)];
                }
                int index = 0;
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    index = ((index + buffer[num2]) + buffer2[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                }
                num2 = index = 0;
                for (int i = inputOffset; i < totalSize; i++)
                {
                    num2 = (num2 + 1) % 0x100;
                    index = (index + buffer[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                    int num5 = (buffer[num2] + buffer[index]) % 0x100;
                    Data[i] = (byte)(Data[i] ^ buffer[num5]);
                }
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return;
            }
        }

        public static void WriteToLog(string fmt, params object[] args)
        {
            try
            {
                string filePath = string.Format("Logs.txt");
                string formatted = string.Format(fmt, args);
                File.AppendAllText(filePath, string.Format("{0}: {1}\r\n", DateTime.Now.ToString(), formatted));
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
                return;
            }
        }

        public static string[] GetIPAddresses()
        {
            try
            {
                return File.ReadAllLines("IPList.txt");
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return new string[] { "0" };
            }
        }

        private static string[] GetCPUKeyList()
        {
            try
            {
                return File.ReadAllLines("CPUKeyList.txt");
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
                return new string[] { "0" };
            }
        }

        public static bool AuthorizedCPUKey(byte[] cpuKey)
        {
            foreach (string bList in GetCPUKeyList())
                if (bList == BytesToHexString(cpuKey)) return true;

            return false;
        }

        public static bool AuthorizedIP(TcpClient client)
        {
            try
            {
                IPEndPoint ip = client.Client.RemoteEndPoint as IPEndPoint;

                // IP check 
                foreach (string ipAddr in GetIPAddresses())
                    if (ipAddr == ip.Address.ToString()) goto Passed;

                // IP didn't exist on auth'd list
                Console.WriteLine("IP {0} not authorized!", ip.ToString());
                return false;

                // IP was authorized
                Passed:

                return true;
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return false;
            }
        }

        public static void CloseConnection(TcpClient client)
        {
            try
            {
                if (client.Connected && client.Client.Connected)
                {
                    client.Close();
                }
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return;
            }
        }

        public static string WindowsCmdExec(string cmd)
        {
            try
            {
                var process = new Process()
                {
                    StartInfo = new ProcessStartInfo("cmd")
                    {
                        UseShellExecute = false,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        Arguments = string.Format("/c \"{0}\"", cmd)
                    }
                };
                process.Start();
                return process.StandardOutput.ReadToEnd();
            }
            catch (Exception ex)
            {
                WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }
    }
}