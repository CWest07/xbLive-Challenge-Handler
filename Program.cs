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
using System.Diagnostics;
using XeCryptDotNet.RSA;
using XeCryptDotNet.Utilities;
using XeCryptDotNet.Structures;

namespace xbLive_API
{
    class Program
    {
        private static string LastBannedIP;
        static byte[] HV_DEC;
        static byte[] HV_RESP_TEMP;
        static byte[] HV_RSA_KEY;
        static int NumberOfPairs;
        static int ServerPort;

        public static byte[][] saltsArray = new byte[256][];

        public enum CONFIG_VALUES : int
        {
            PAIRSCOUNT,
            PORT
        }

        private static TcpListener server;

        public static void LoadSaltArray()
        {
            try
            { 
                byte[] saltBuffer = File.ReadAllBytes("HV\\HV_SALTS.bin");

                for (int x = 0; x < saltsArray.Length; x++)
                {
                    saltsArray[x] = new byte[0x10];
                }

                for (int i = 0; i < 256; i++)
                {
                    Buffer.BlockCopy(saltBuffer, i * 0x10, saltsArray[i], 0, 0x10);
                }
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return;
            }
        }

        public static bool IsRealSalt(byte[] HvSalt)
        {
            try
            {
                for (int i = 0; i < 256; i++)
                {
                    if (Binary.ByteArrayCompare(HvSalt, saltsArray[i]))
                        return true;

                    continue;
                }
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return false;
            }
            return false;
        }

        private static int FindEncryptionKey(byte[] clientSession)
        {
            try
            {
                int increment = 0;
                for (int i = 0; i < 4; ++i)
                {
                    increment += clientSession[4 - i]; // increment += clientSession[i]; 
                    increment = increment % NumberOfPairs;
                }
                return increment;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return 0;
            }
        }

        private static byte[] ComputeHvDigest(byte[] salt)
        {
            try
            {
                byte[] hvHash = new byte[0x14];

                /* 16203 - 17544
                Hash.TransformBlock(salt, 0, 0x10, null, 0);
                Hash.TransformBlock(HV_DEC, 0x34, 0x40, null, 0);
                Hash.TransformBlock(HV_DEC, 0x78, 0xF88, null, 0);
                Hash.TransformBlock(HV_DEC, 0x100C0, 0x40, null, 0);
                Hash.TransformBlock(HV_DEC, 0x10350, 0xDF0, null, 0);
                Hash.TransformBlock(HV_DEC, 0x16D20, 0x2E0, null, 0);
                Hash.TransformBlock(HV_DEC, 0x20000, 0xFFC, null, 0);
                Hash.TransformFinalBlock(HV_DEC, 0x30000, 0xFFC);*/

                SHA1Managed Hash = new SHA1Managed();
                Hash.TransformBlock(salt, 0, 0x10, null, 0);
                Hash.TransformBlock(HV_DEC, 0x34, 0x40, null, 0);
                Hash.TransformBlock(HV_DEC, 0x78, 0xFF88, null, 0);
                Hash.TransformBlock(HV_DEC, 0x100C0, 0x40, null, 0);
                Hash.TransformBlock(HV_DEC, 0x10350, 0x5F70, null, 0);
                Hash.TransformBlock(HV_DEC, 0x16EA0, 0x9160, null, 0);
                Hash.TransformBlock(HV_DEC, 0x20000, 0xFFFF, null, 0);
                Hash.TransformFinalBlock(HV_DEC, 0x30000, 0xFFFF);

                Buffer.BlockCopy(Hash.Hash, 0, hvHash, 0, 0x14);
                Hash.Dispose();

                return hvHash;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static byte[] ComputeECCDigest(byte[] saltChecksum, int keySelect)
        {
            try
            {
                byte[] hvECCHash = new byte[0x14];
                byte[] HV_CACHE = new byte[0x1000];
                byte[] HV_ENC = new byte[0x40000];

                HV_CACHE = File.ReadAllBytes("Seeds\\" + keySelect + "\\cache.bin");
                HV_ENC = File.ReadAllBytes("Seeds\\" + keySelect + "\\HV_enc.bin");

                 /* 16203 - 17544
                 Hash.TransformBlock(saltChecksum, 0, 2, null, 0);
                 Hash.TransformBlock(HV_DEC, 0x34, 0xC, null, 0);
                 Hash.TransformBlock(HV_ENC, 0x40, 0x30, null, 0);
                 Hash.TransformBlock(HV_DEC, 0x70, 4, null, 0);
                 Hash.TransformBlock(HV_DEC, 0x78, 8, null, 0);
                 Hash.TransformBlock(HV_CACHE, 2, 0x3FE, null, 0);
                 Hash.TransformBlock(HV_ENC, 0x100C0, 0x40, null, 0);
                 Hash.TransformBlock(HV_ENC, 0x10350, 0x30, null, 0);
                 Hash.TransformBlock(HV_CACHE, 0x40E, 0x176, null, 0);
                 Hash.TransformBlock(HV_ENC, 0x16100, 0x40, null, 0);
                 Hash.TransformBlock(HV_ENC, 0x16D20, 0x60, null, 0);
                 Hash.TransformBlock(HV_CACHE, 0x5B6, 0x24A, null, 0);
                 Hash.TransformBlock(HV_CACHE, 0x800, 0x400, null, 0);
                 Hash.TransformFinalBlock(HV_CACHE, 0xC00, 0x400);*/

                SHA1Managed Hash = new SHA1Managed();
                Hash.TransformBlock(saltChecksum, 0, 2, null, 0);
                Hash.TransformBlock(HV_DEC, 0x34, 0xC, null, 0);
                Hash.TransformBlock(HV_ENC, 0x40, 0x30, null, 0);
                Hash.TransformBlock(HV_DEC, 0x70, 0x4, null, 0);
                Hash.TransformBlock(HV_DEC, 0x78, 0x8, null, 0);
                Hash.TransformBlock(HV_CACHE, 0x2, 0x3FE, null, 0);
                Hash.TransformBlock(HV_ENC, 0x100C0, 0x40, null, 0);
                Hash.TransformBlock(HV_ENC, 0x10350, 0x30, null, 0);
                Hash.TransformBlock(HV_CACHE, 0x40E, 0x17C, null, 0);
                Hash.TransformBlock(HV_ENC, 0x16280, 0x40, null, 0);
                Hash.TransformBlock(HV_ENC, 0x16EA0, 0x60, null, 0);
                Hash.TransformBlock(HV_CACHE, 0x5BC, 0x244, null, 0);
                Hash.TransformBlock(HV_CACHE, 0x800, 0x400, null, 0);
                Hash.TransformFinalBlock(HV_CACHE, 0xC00, 0x400);

                Buffer.BlockCopy(Hash.Hash, 0, hvECCHash, 0, 0x14);
                Hash.Dispose();

                return hvECCHash;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static byte[] FindSaltFile(byte[] clientHvSalt, int keySelect)
        {
            try
            {
                byte[] saltDump = new byte[0x40];

                if (clientHvSalt == null || Binary.ByteArrayEmpty(clientHvSalt))
                    return null;

                saltDump = File.ReadAllBytes("Seeds\\" + keySelect + "\\Salts\\0x" + Utils.BytesToHexString(clientHvSalt) + ".bin");

                return saltDump;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static byte[] HvSetupShaSaltedHash(byte[] salt, int saltLength, byte[] rsaKey, int rsaKeyLength)
        {
            try
            {
                int Increment = 0;

                for (int s = 0; s < rsaKeyLength; s += 0x14)
                {
                    int Subsize = (s + 0x14 > rsaKeyLength) ? rsaKeyLength - s : 0x14;
                    byte[] output = new byte[0x14];
                    SHA1Managed managed = new SHA1Managed();
                    managed.TransformBlock(salt, 0, saltLength, null, 0);
                    managed.TransformFinalBlock(new byte[] { 0, 0, 0, (byte)Increment }, 0, 4);
                    output = managed.Hash;
                    for (int l = 0; l < Subsize; l++)
                    {
                        rsaKey[s + l] ^= output[l];
                    }
                    Increment++;
                    managed.Dispose();
                }
                return rsaKey;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static byte[] HvSetupMemEncryptionKey(byte[] memEncSeed, byte[] RandomData)
        {
            try
            {
                byte[] HvData = { 0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09 };
                byte[] Empty = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                byte[] memoryRsaKey = new byte[0x80];

                memoryRsaKey[0] = 0;

                Buffer.BlockCopy(RandomData, 0, memoryRsaKey, 1, 0x14);
                Buffer.BlockCopy(HvData, 0, memoryRsaKey, 0x15, 0x14);
                Buffer.BlockCopy(Empty, 0, memoryRsaKey, 0x29, 0x26);

                memoryRsaKey[0x4F] = 1;

                Buffer.BlockCopy(memEncSeed, 0, memoryRsaKey, 0x50, 0x30);

                byte[] tmp = new byte[0x6B];
                Buffer.BlockCopy(memoryRsaKey, 0x15, tmp, 0, 0x6B);
                Buffer.BlockCopy(HvSetupShaSaltedHash(RandomData, 0x14, tmp, 0x6B), 0, memoryRsaKey, 0x15, 0x6B);

                Buffer.BlockCopy(memoryRsaKey, 0x15, tmp, 0, 0x6B);
                Buffer.BlockCopy(HvSetupShaSaltedHash(tmp, 0x6B, RandomData, 0x14), 0, memoryRsaKey, 1, 0x14);

                return memoryRsaKey;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static byte[] ComputeRSAOutput(byte[] clientSession, int keySelect)
        {
            try
            {
                byte[] memoryKey = new byte[0x30];

                memoryKey = File.ReadAllBytes("Seeds\\" + keySelect + "\\Key.bin");

                byte[] shaSalt = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, clientSession[6], clientSession[8] };
                Buffer.BlockCopy(clientSession, 0, shaSalt, 0, 0x10);

                byte[] RsaData = HvSetupMemEncryptionKey(memoryKey, shaSalt);

                Array.Reverse(RsaData);
                RsaData = Binary.bswap64(RsaData);
                RsaData = XeCryptRSA.PubCrypt(RsaData, HV_RSA_KEY);
                RsaData = Binary.bswap64(RsaData);
           
                return RsaData;
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);
                return null;
            }
        }

        private static bool HandleXeKeysExecuteResponse(TcpClient client, byte[] data, NetworkStream Stream, byte[] cpuKey, List<Log.PrintQueue> logId)
        {
            try
            {
                byte[] eccSalt = new byte[0x2];
                byte[] hvExecAddr = new byte[0x2];
                byte[] salt = new byte[0x10];
                byte[] sessionToken = new byte[0x10];
                byte[] HvSalt = new byte[0x10];
                byte[] responseBuff = new byte[0x120];
                byte[] cpukeyFromKV = new byte[0x10];
                bool typeOneKv = Convert.ToBoolean(data[0x40]);
                bool fcrt = Convert.ToBoolean(data[0x41]);
                bool crl = Convert.ToBoolean(data[0x42]);
                bool fakeData = Convert.ToBoolean(data[0x43]);

                string ipAddress = client.Client.RemoteEndPoint.ToString().Split(new char[] { ':' })[0];

                // Generate random RC4 key for encrypted data
                byte[] eccHashEncryptionKey = XeCryptDotNet.PRNG.XeCryptPRNG.RandomBytes(0x20);

                // Copy the salt and session token
                Buffer.BlockCopy(data, 0x0, salt, 0x0, 0x10);
                Buffer.BlockCopy(data, 0x10, sessionToken, 0x0, 0x10);
                Buffer.BlockCopy(data, 0x30, cpukeyFromKV, 0x0, 0x10);

                // Print some info
                Log.Add(logId, ConsoleColor.Cyan, "Info", string.Format("CPU Key: {0}", Utils.BytesToHexString(cpuKey)), ipAddress);
                Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Salt: {0}", Utils.BytesToHexString(salt)), ipAddress);
                Log.Add(logId, ConsoleColor.Yellow, "Info", string.Format("Session Token: {0}", Utils.BytesToHexString(sessionToken)), ipAddress);


                // Validate the salt & session token
                if (Binary.ByteArrayEmpty(salt) || Binary.ByteArrayEmpty(sessionToken) || Binary.ByteArrayEmpty(cpuKey) || Binary.ByteArrayEmpty(cpukeyFromKV))
                {
                    Console.WriteLine("Salt, Session, or CPUKey was null!");
                    Utils.WriteToLog("Salt, Session, or CPUKey was null! {0}", Utils.BytesToHexString(cpuKey));
                    return false;
                }

                // Make sure it's a real CPUKey
                if (!Binary.CpuKeyValid(cpuKey))
                {
                    Console.WriteLine("CPUKey {0} is not a valid CPUKey!", Utils.BytesToHexString(cpuKey));
                    Utils.WriteToLog("CPUKey {0} is not a valid CPUKey!", Utils.BytesToHexString(cpuKey));
                    return false;
                }

                // Make sure it's a real salt
                if (!IsRealSalt(salt))
                {
                    Console.WriteLine("Client: {0} has fake salt: {1}", Utils.BytesToHexString(cpuKey), Utils.BytesToHexString(salt));
                    Utils.WriteToLog("Client: {0} has fake salt: {1}", Utils.BytesToHexString(cpuKey), Utils.BytesToHexString(salt));
                    return false;
                }

                // Select a memory encryption key to use
                int encryptionKeySelect = FindEncryptionKey(sessionToken);
                Log.Add(logId, ConsoleColor.Cyan, "Info", string.Format("Seed Package: {0}", encryptionKeySelect), ipAddress);

                // Find the ecc salt & hv executing address from salt
                byte[] saltFile = FindSaltFile(salt, encryptionKeySelect);
                if (Binary.ByteArrayEmpty(saltFile) || saltFile == null)
                {
                    Console.WriteLine("Failed to find salt: {0}", Utils.BytesToHexString(salt));
                    Utils.WriteToLog("Failed to find salt: {0} in {1} pair!", Utils.BytesToHexString(salt), encryptionKeySelect);
                    return false;
                }

                // Copy over data from the salt dump we are using
                Buffer.BlockCopy(saltFile, 0, HvSalt, 0, 0x10);
                Buffer.BlockCopy(saltFile, 0x20, eccSalt, 0, 0x2);
                Buffer.BlockCopy(saltFile, 0x30, hvExecAddr, 0, 0x2);

                // Make sure the salts match
                if (!Binary.ByteArrayCompare(HvSalt, salt))
                {
                    Console.WriteLine("Salt mismatch!: {0}", Utils.BytesToHexString(salt));
                    Utils.WriteToLog("Salt mismatch!: {0}", Utils.BytesToHexString(salt));
                    return false;
                }

                // Copy the response template, HV executing address, & console values to response buffer
                Buffer.BlockCopy(HV_RESP_TEMP, 0, responseBuff, 0, 0x120);
                Buffer.BlockCopy(hvExecAddr, 0, responseBuff, 0xF8, 0x2);

                // RSA sign the currently selected memory key we used to generate our response
                byte[] rsaOut = ComputeRSAOutput(sessionToken, encryptionKeySelect);
                if (Binary.ByteArrayEmpty(rsaOut) || rsaOut == null)
                {
                    Console.WriteLine("Failed to generate rsa data: {0}", Utils.BytesToHexString(sessionToken));
                    Utils.WriteToLog("Failed to generate rsa data: {0} for pair {1}", Utils.BytesToHexString(sessionToken), encryptionKeySelect);
                    return false;
                }

                // Generate and copy ECC hash, HV hash & RSA'd memory key to the response buffer
                Buffer.BlockCopy(ComputeECCDigest(eccSalt, encryptionKeySelect), 0, responseBuff, 0x50, 0x14);
                Buffer.BlockCopy(ComputeHvDigest(salt), 0xE, responseBuff, 0xFA, 0x6);
                Buffer.BlockCopy(rsaOut, 0, responseBuff, 0x78, 0x80);

                // Copy some console data in
                Buffer.BlockCopy(Utils.intToArray(typeOneKv ? Utils.ReverseBytes(0x0304000E) : Utils.ReverseBytes(0x0304000E)), 0, responseBuff, 0x3C, 0x4);
                Buffer.BlockCopy(Utils.intToArray(fcrt ? Utils.ReverseBytes(0x033289D3) : Utils.ReverseBytes(0x023289D3)), 0, responseBuff, 0x38, 0x4);
                if (crl) Buffer.BlockCopy(Utils.intToArray(fcrt ? Utils.ReverseBytes(0x033389D3) : Utils.ReverseBytes(0x023389D3)), 0, responseBuff, 0x38, 0x4);

                // Print if the CPUKey from KV is real or not & hash it
                Log.Add(logId, ConsoleColor.DarkCyan, "Info", string.Format("KV CPU Key: {0}", Binary.CpuKeyValid(cpukeyFromKV) ? "Valid" : "Invalid"), ipAddress);
                Buffer.BlockCopy(new SHA1Managed().ComputeHash(cpukeyFromKV), 0, responseBuff, 0x64, 0x14);

                // If we want to fake the data because someone has sent more than 50 challenges
                if (fakeData)
                {
                    SHA1Managed Hash = new SHA1Managed();
                    Hash.TransformBlock(salt, 0, 0x10, null, 0);
                    Hash.TransformFinalBlock(sessionToken, 0, 0x10);
                    Buffer.BlockCopy(Hash.Hash, 0, responseBuff, 0x50, 0x14);

                    Log.Add(logId, ConsoleColor.Red, "Reporting", "Sending fake data!", ipAddress);
                    Utils.WriteToLog("Sending fake data to CPUKey: {0}", Utils.BytesToHexString(cpuKey));
                }

                byte[] encryptedECCHash = new byte[0x14];
                Buffer.BlockCopy(responseBuff, 0x50, encryptedECCHash, 0, 0x14);

                // Encrypt the ECC hash to prevent data stealing
                Utils.RC4(ref encryptedECCHash, eccHashEncryptionKey);

                // Copy RC4'd ECC hash to the response buffer
                Buffer.BlockCopy(encryptedECCHash, 0, responseBuff, 0x50, 0x14);

                // Copy the RC4 key to the end of the response buffer
                Buffer.BlockCopy(eccHashEncryptionKey, 0, responseBuff, 0x100, 0x20);

                // Encrypt our full response
                Utils.RC4(ref responseBuff, sessionToken);

                // Send the response
                Stream.Write(responseBuff, 0x0, 0x120);

                // Success
                return true;
            }

            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.Write(ex.Message);

                return false;
            }
        }

        private static void ClientConnectedThread(object arg)
        {
            TcpClient client = (TcpClient)arg;
            IPEndPoint ip = client.Client.RemoteEndPoint as IPEndPoint;
            string ipAddress = client.Client.RemoteEndPoint.ToString().Split(new char[] {  ':' })[0];

            if (Utils.AuthorizedIP(client) == false)
            {
                LastBannedIP = ipAddress;
                if (ipAddress != LastBannedIP)
                {
                    LastBannedIP = ipAddress;
                    Utils.WindowsCmdExec(string.Format("netsh advfirewall firewall add rule name=\"" + "BAD_IP_BAN@{0}\" " + "dir=in interface=any action=block remoteip={0}", ipAddress));
                    Utils.CloseConnection(client);
                    Utils.WriteToLog("Un-authorized IP address: {0}", ip.ToString());
                }

                return;
            }

            List<Log.PrintQueue> logId = Log.GetQueue();

            try
            {
                byte[] data = new byte[0x44];
                byte[] CpuKey = new byte[0x10];

                DateTime CurrentTime = DateTime.Now;
                NetworkStream stream = client.GetStream();
                int i = stream.Read(data, 0, data.Length);
                if (i == 0x44 && !Binary.ByteArrayEmpty(data))
                {
                    Buffer.BlockCopy(data, 0x20, CpuKey, 0x0, 0x10);
                    if (!HandleXeKeysExecuteResponse(client, data, stream, CpuKey, logId))
                    {
                        Log.Print(logId);

                        Utils.CloseConnection(client);
                        Utils.WriteToLog("Failed to generate response exception! {0}", Utils.BytesToHexString(CpuKey));

                        Log.Print(logId);
                        Utils.CloseConnection(client);
                        return;
                    }

                    Log.Add(logId, ConsoleColor.Green, "Status", "Response Generation Success!", ipAddress);
                }
                else
                {
                    Console.WriteLine("Unknown Request Size: {0} at {1} via {2}", i, CurrentTime.ToString(), ip.ToString());
                    Console.WriteLine("========================================================");
                    Utils.WriteToLog("Unknown Request Size: {0} at {1} via {2}", i, CurrentTime.ToString(), ip.ToString());
                    Utils.CloseConnection(client);
                    return;
                }
            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.WriteLine(ex.ToString());
                return;
            }

            Log.Print(logId);
            Utils.CloseConnection(client);
        }

        private static void HandleClientConnectionThread()
        {
            server.Start();
            while (true)
            {
                try
                {
                    Thread.Sleep(100);
                    if (server.Pending())
                        new Thread(new ParameterizedThreadStart(ClientConnectedThread)).Start(server.AcceptTcpClient());

                }
                catch (Exception ex)
                {
                    Utils.WriteToLog(ex.Message);
                    Console.Write(ex.Message);
                }
            }
        }

        static void Main(string[] args)
        {

            // Setup the app look
            Console.ForegroundColor = ConsoleColor.White;
            Console.WindowWidth = 95;
            Console.WindowHeight = 31;
            Console.Title = "xbLive Challenge Handler";

            // Read our file to check our port & number of pairs
            string[] config = File.ReadAllLines("config.ini");

            // This will be the number of packages we can use to generate a response
            NumberOfPairs = int.Parse(config[(int)CONFIG_VALUES.PAIRSCOUNT]);

            // This of course, is the port the server will run on
            ServerPort = int.Parse(config[(int)CONFIG_VALUES.PORT]);

            // Read in our default clean HV once
            HV_DEC = File.ReadAllBytes("HV\\HV_DEC.bin");

            // Read in our default response template once
            HV_RESP_TEMP = File.ReadAllBytes("HV\\HV_RESP_TEMPLATE.bin");

            // Read the public RSA key
            HV_RSA_KEY = File.ReadAllBytes("HV\\HV_pub.bin");

            // Load the salts 
            LoadSaltArray();

            // Make sure we didn't goof anything...
            if (NumberOfPairs == 0 || ServerPort == 0 || (HV_DEC == null || Binary.ByteArrayEmpty(HV_DEC)) || (HV_RESP_TEMP == null || Binary.ByteArrayEmpty(HV_RESP_TEMP)) || (HV_RSA_KEY == null || Binary.ByteArrayEmpty(HV_RSA_KEY)))
            {
                Utils.WriteToLog("Error Reading API Files");
                Console.WriteLine("Error reading API files!");
            }

            // Start the listener
            server = new TcpListener(IPAddress.Any, ServerPort);

            // Begin the thread
            try
            {
                new Thread(new ThreadStart(HandleClientConnectionThread)).Start();
                Console.WriteLine("xbLive Challenge Handler has started on port {0}", ServerPort);
                Console.WriteLine(" ");

            }
            catch (Exception ex)
            {
                Utils.WriteToLog(ex.Message);
                Console.WriteLine(ex.ToString());
            }
        }
    }
}