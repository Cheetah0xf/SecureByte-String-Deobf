using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.IO;
using System.Reflection;
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
            Console.WriteLine(">>SecureByte String Deobfuscator By Cheetah.");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Cyan;

            //TAKING INPUT
            if (args.Length != 0)
                input = args[0].Replace("\"", string.Empty);

            while (!File.Exists(input))
            {
                Console.WriteLine("Enter valid file path: ");
                input = Console.ReadLine().Replace("\"", string.Empty);
            }

            ModuleDefMD module = ModuleDefMD.Load(input);
            //OUTPUT PATH OF DEOBFUSCATED ASSEMBLY
            output = input.Insert(input.Length - 4, "-decrypted");

            try
            {
                Assembly runtimeAssembly = Assembly.LoadFile(input);



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
                                instructions[i + 2].OpCode == OpCodes.Call
                                ) //PATTERN MATCHING
                            {



                                string operand = instructions[i].Operand.ToString();
                                string[] parts = operand.Split(new[] { ' ', ':' }, StringSplitOptions.RemoveEmptyEntries);

                                string className = parts[1];
                                string fieldName = parts[2];


                                Console.WriteLine($"Class: {className} and Field: {fieldName}");


                                Module mod = runtimeAssembly.ManifestModule;
                                FieldInfo fieldInfo;
                                if (className == "<Module>")
                                {
                                    fieldInfo = mod.GetField(fieldName, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                }
                                else
                                {
                                    Type runtimeTyp = runtimeAssembly.GetType(className);
                                    if (runtimeTyp == null)
                                    {
                                        Console.WriteLine($"Error: Type '{className}' not found in the assembly.");
                                        return;
                                    }
                                    fieldInfo = runtimeTyp.GetField(fieldName, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);

                                }

                                object cachedStringsList = fieldInfo.GetValue(null);

                                if (instructions[i + 2].Operand is MethodDef decryptionMethod)
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine($"Found decryption method: {decryptionMethod.FullName}");
                                    Console.ForegroundColor = ConsoleColor.Cyan;
                                    Type runtimeType = runtimeAssembly.GetType(decryptionMethod.DeclaringType.FullName);
                                    MethodInfo decryptionMethodInfo = runtimeType.GetMethod(decryptionMethod.Name, BindingFlags.Public | BindingFlags.Static);



                                    object[] argss =
                                    {
                                            cachedStringsList,
                                            instructions[i + 1].GetLdcI4Value()

                                    };



                                    try
                                    {
                                        object result = decryptionMethodInfo.Invoke(null, argss);
                                        if (result is string decryptedString)
                                        {
                                            //REPLACING DEOBFUSCATED STRINGS
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

                //SAVING THE ASSEMBLY
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
    }
}
