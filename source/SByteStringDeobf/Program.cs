using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;
using System.Text;



//SECUREBYTE STRING DEOBFUSCATOR
//IT CAN BE IMPROVED MORE
//SO FEEL FREE TO LET ME KNOW WHAT  I SHOULD IMPROVE
//SHARE WITH CREDITS https://github.com/Cheetah0xf/

namespace SByteStringDeobf
{
    internal class Program
    {
        static string input;
        static string output;

         static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "SecureByte String Deobfuscator";
            Console.WriteLine(">>SecureByte String Deobfuscator By Cheetah0xf.");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Cyan;


            if (args.Length != 0)
                input = args[0].Replace("\"", string.Empty);

            while (!File.Exists(input))
            {
                Console.WriteLine("Enter valid file path: ");
                input = Console.ReadLine().Replace("\"", string.Empty);
            }

            ModuleDefMD module = ModuleDefMD.Load(input);
            output = input.Insert(input.Length - 4, "-decrypted");

            try
            {
                Console.WriteLine("Searching for Resource...");
                string resourceName = FindResName(module);
                if (resourceName == null)
                {
                    Console.WriteLine("Resource not found.");
                    return;
                }
                Console.WriteLine($"Resource found: {resourceName}");
                var resource = module.Resources.Find(resourceName);
                if (resource is EmbeddedResource embeddedResource)
                {
                    byte[] resourceBytes;
                    using (var stream = embeddedResource.CreateReader().AsStream())
                    using (var memoryStream = new MemoryStream())
                    {
                        stream.CopyTo(memoryStream);
                        resourceBytes = memoryStream.ToArray();
                    }
                    byte[] decompressedBytes = QuickLZ.DecompressBytes(resourceBytes, 2);
                    Dictionary<int, string> decompressedStrings = ReadStringsFromBytes(decompressedBytes);
                    DecryptStrings(decompressedStrings,module);
                }

                var opts = new ModuleWriterOptions(module)
                {
                    MetadataOptions = { Flags = MetadataFlags.PreserveAll },
                    Logger = DummyLogger.NoThrowInstance
                };
                module.Write(output, opts);
                Console.WriteLine($"Saved to {output}");
            }

            catch (Exception ex)
            {
                Console.WriteLine($"Error during processing: {ex.Message}");
            }

            Console.WriteLine("Decryption Done!");
            Console.ReadKey();
        }
        public static void DecryptStrings(Dictionary<int, string> encStrings , ModuleDefMD module)
        {
            Assembly runtimeAssembly = Assembly.LoadFile(input);
            string[] cachedStrings = encStrings.Values.ToArray();

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions)
                        continue;
                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Ldsfld &&
                           instructions[i + 1].IsLdcI4() &&
                           instructions[i + 2].OpCode == OpCodes.Call)
                        {
                            if (instructions[i + 2].Operand is MethodDef decryptionMethod)
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"Found decryption method: {decryptionMethod.FullName}");
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Type runtimeType = runtimeAssembly.GetType(decryptionMethod.DeclaringType.FullName);
                                MethodInfo decryptionMethodInfo = runtimeType.GetMethod(decryptionMethod.Name, BindingFlags.Public | BindingFlags.Static);

                                object[] argss =
                                    {
                                            cachedStrings,
                                            instructions[i + 1].GetLdcI4Value()
                                    };

                                try
                                {
                                    object result = decryptionMethodInfo.Invoke(null, argss);
                                    if (result is string decryptedString)
                                    {
                                        
                                        Console.WriteLine($"Decrypted string: {decryptedString}");
                                        instructions[i].OpCode = OpCodes.Ldstr;
                                        instructions[i].Operand = decryptedString;
                                        instructions[i + 1].OpCode = OpCodes.Nop;
                                        instructions[i + 2].OpCode = OpCodes.Nop;

                                    }

                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Error invoking decryption method: {ex.Message}");
                                }

                            }
                            else
                            {
                                Console.WriteLine("Error: Operand at i + 2 is not a MethodDef.");
                            }
                        }
                    }
                }
            }
        }
        static string FindResName(ModuleDefMD module)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        if (
                            instructions[i].OpCode == OpCodes.Newarr &&
                            instructions[i + 1].OpCode == OpCodes.Stsfld &&
                            instructions[i + 2].OpCode == OpCodes.Ldtoken &&
                            instructions[i + 3].OpCode == OpCodes.Call &&
                            instructions[i + 4].OpCode == OpCodes.Callvirt &&
                            instructions[i + 5].OpCode == OpCodes.Ldstr &&
                            instructions[i + 6].OpCode == OpCodes.Callvirt &&
                            instructions[i + 6].Operand is IMethod methodOperand &&
                            methodOperand.Name == "GetManifestResourceStream")
                        {
                            string resName = instructions[i + 5].Operand.ToString();
                            return resName;
                        }
                    }
                }
            }
            return null;
        }
        static Dictionary<int, string> ReadStringsFromBytes(byte[] data)
        {
            var result = new Dictionary<int, string>();
            using (var memoryStream = new MemoryStream(data))
            using (var streamReader = new StreamReader(memoryStream))
            {
                string line;
                int lineNumber = 0;

                while ((line = streamReader.ReadLine()) != null)
                {
                    result[lineNumber++] = line;
                }
            }

            return result;
        }
        public static class QuickLZ
        {
            public const int QLZ_VERSION_MAJOR = 1;
            public const int QLZ_VERSION_MINOR = 5;
            public const int QLZ_VERSION_REVISION = 0;
            public const int QLZ_STREAMING_BUFFER = 0;
            public const int QLZ_MEMORY_SAFE = 0;
            private const int HASH_VALUES = 4096;
            private const int UNCONDITIONAL_MATCHLEN = 6;
            private const int UNCOMPRESSED_END = 4;
            private const int CWORD_LEN = 4;
            public static byte[] DecompressBytes(byte[] source, int rnd)
            {
                int level;
                byte[] add = new byte[] { (byte)rnd };
                byte[] concat = source.Concat(add).ToArray();
                source = concat;
                int size = SizeDecompressed(source);
                int src = HeaderLen(source);
                int dst = 0;
                uint cword_val = 1;
                byte[] destination = new byte[size];
                int[] hashtable = new int[4096];
                byte[] hash_counter = new byte[4096];
                int last_matchstart = size - UNCONDITIONAL_MATCHLEN - UNCOMPRESSED_END - 1;
                int last_hashed = -1;
                int hash;
                uint fetch = 0;

                level = (source[0] >> 2) & 0x3;

                if (level != 1 && level != 3)
                    throw new ArgumentException("C# version only supports level 1 and 3");

                if ((source[0] & 1) != 1)
                {
                    byte[] d2 = new byte[size];
                    System.Array.Copy(source, HeaderLen(source), d2, 0, size);
                    return d2;
                }

                for (; ; )
                {
                    if (cword_val == 1)
                    {
                        cword_val = (uint)(source[src] | (source[src + 1] << 8) | (source[src + 2] << 16) | (source[src + 3] << 24));
                        src += 4;
                        if (dst <= last_matchstart)
                        {
                            if (level == 1)
                                fetch = (uint)(source[src] | (source[src + 1] << 8) | (source[src + 2] << 16));
                            else
                                fetch = (uint)(source[src] | (source[src + 1] << 8) | (source[src + 2] << 16) | (source[src + 3] << 24));
                        }
                    }

                    if ((cword_val & 1) == 1)
                    {
                        uint matchlen;
                        uint offset2;

                        cword_val = cword_val >> 1;

                        if (level == 1)
                        {
                            hash = ((int)fetch >> 4) & 0xfff;
                            offset2 = (uint)hashtable[hash];

                            if ((fetch & 0xf) != 0)
                            {
                                matchlen = (fetch & 0xf) + 2;
                                src += 2;
                            }
                            else
                            {
                                matchlen = source[src + 2];
                                src += 3;
                            }
                        }
                        else
                        {
                            uint offset;
                            if ((fetch & 3) == 0)
                            {
                                offset = (fetch & 0xff) >> 2;
                                matchlen = 3;
                                src++;
                            }
                            else if ((fetch & 2) == 0)
                            {
                                offset = (fetch & 0xffff) >> 2;
                                matchlen = 3;
                                src += 2;
                            }
                            else if ((fetch & 1) == 0)
                            {
                                offset = (fetch & 0xffff) >> 6;
                                matchlen = ((fetch >> 2) & 15) + 3;
                                src += 2;
                            }
                            else if ((fetch & 127) != 3)
                            {
                                offset = (fetch >> 7) & 0x1ffff;
                                matchlen = ((fetch >> 2) & 0x1f) + 2;
                                src += 3;
                            }
                            else
                            {
                                offset = (fetch >> 15);
                                matchlen = ((fetch >> 7) & 255) + 3;
                                src += 4;
                            }
                            offset2 = (uint)(dst - offset);
                        }

                        destination[dst + 0] = destination[offset2 + 0];
                        destination[dst + 1] = destination[offset2 + 1];
                        destination[dst + 2] = destination[offset2 + 2];

                        for (int i = 3; i < matchlen; i += 1)
                        {
                            destination[dst + i] = destination[offset2 + i];
                        }

                        dst += (int)matchlen;

                        if (level == 1)
                        {
                            fetch = (uint)(destination[last_hashed + 1] | (destination[last_hashed + 2] << 8) | (destination[last_hashed + 3] << 16));
                            while (last_hashed < dst - matchlen)
                            {
                                last_hashed++;
                                hash = (int)(((fetch >> 12) ^ fetch) & (HASH_VALUES - 1));
                                hashtable[hash] = last_hashed;
                                hash_counter[hash] = 1;
                                fetch = (uint)(fetch >> 8 & 0xffff | destination[last_hashed + 3] << 16);
                            }
                            fetch = (uint)(source[src] | (source[src + 1] << 8) | (source[src + 2] << 16));
                        }
                        else
                        {
                            fetch = (uint)(source[src] | (source[src + 1] << 8) | (source[src + 2] << 16) | (source[src + 3] << 24));
                        }
                        last_hashed = dst - 1;
                    }
                    else
                    {
                        if (dst <= last_matchstart)
                        {
                            destination[dst] = source[src];
                            dst += 1;
                            src += 1;
                            cword_val = cword_val >> 1;

                            if (level == 1)
                            {
                                while (last_hashed < dst - 3)
                                {
                                    last_hashed++;
                                    int fetch2 = destination[last_hashed] | (destination[last_hashed + 1] << 8) | (destination[last_hashed + 2] << 16);
                                    hash = ((fetch2 >> 12) ^ fetch2) & (HASH_VALUES - 1);
                                    hashtable[hash] = last_hashed;
                                    hash_counter[hash] = 1;
                                }
                                fetch = (uint)(fetch >> 8 & 0xffff | source[src + 2] << 16);
                            }
                            else
                            {
                                fetch = (uint)(fetch >> 8 & 0xffff | source[src + 2] << 16 | source[src + 3] << 24);
                            }
                        }
                        else
                        {
                            while (dst <= size - 1)
                            {
                                if (cword_val == 1)
                                {
                                    src += CWORD_LEN;
                                    cword_val = 0x80000000;
                                }

                                destination[dst] = source[src];
                                dst++;
                                src++;
                                cword_val = cword_val >> 1;
                            }
                            return destination;
                        }
                    }
                }
            }
            public static int HeaderLen(byte[] source)
            {
                return ((source[0] & 2) == 2) ? 9 : 3;
            }
            public static int SizeDecompressed(byte[] source)
            {
                if (HeaderLen(source) == 9)
                    return source[5] | (source[6] << 8) | (source[7] << 16) | (source[8] << 24);

                return source[2];
            }
        }
    }
}
