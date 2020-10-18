/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_3ds;

import java.io.IOException;
import java.util.*;

import adubbz.nx.loader.common.MemoryBlockHelper;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Ghidra_3DSLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Nintendo 3DS Binary (CXI)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		// For now just check NCCH magic, worry about CFAs later
		String magic = reader.readAsciiString(0x100, 4);
		if(magic.equals("NCCH")) { 
			// the 3ds is arm11 aka armv6
			// but ghidra machine broke, so we use v7 
			// see https://github.com/NationalSecurityAgency/ghidra/issues/1539
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v7", "default"), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        NCCHFile ncch = new NCCHFile(provider);
        
        ExeFSFile code_file = null;
        
        for(ExeFSFile f: ncch.exefs.files) {
        	if(f.name.equals(".code")) {
        		code_file = f;
        		break;
        	}
        }
        
        if(code_file == null) {
        	throw new IOException(".code not found!");
        }
        byte[] code = provider.readBytes(code_file.offset, code_file.size);
        LZSSContext context = new LZSSContext(code);
        byte[] decompressed_code = context.decompress();

        long text_start = ncch.exheader.text_section.address;
        long text_offset = 0;
        long text_size = ncch.exheader.text_section.size;
        
        long rodata_start = ncch.exheader.rodata_section.address;
        long rodata_offset = rodata_start - text_start;
        long rodata_size = ncch.exheader.rodata_section.size;
        
        long data_start = ncch.exheader.data_section.address;
        long data_offset = data_start - text_start;
        long data_size = ncch.exheader.data_section.size;
        
        long bss_offset = data_offset + data_size;
        long bss_size = ncch.exheader.bss_size;
        
		var space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			program.setImageBase(space.getAddress(ncch.exheader.text_section.address), true);
		} catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        ByteArrayProvider code_provider = new ByteArrayProvider(decompressed_code);
        MemoryBlockHelper helper = new MemoryBlockHelper(monitor, program, code_provider);
        helper.addSection(".text", text_offset, text_offset, text_size, true, false, true);
        helper.addSection(".rodata", rodata_offset, rodata_offset, rodata_size, true, false, false);
        helper.addSection(".data", data_offset, data_offset, data_size, true, true, false);
        
        Address bss_addr = program.getImageBase().add(bss_offset);
        MemoryBlockUtils.createUninitializedBlock(program, false, ".bss", bss_addr, bss_size, "", "", true, true, false, log);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
