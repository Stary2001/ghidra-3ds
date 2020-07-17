package ghidra_3ds;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class CodeSetInfo {
	long address;
	long physical_num_pages;
	long size;
	
	public CodeSetInfo(BinaryReader reader, long offset) throws IOException {
		address = reader.readUnsignedInt(offset);
		physical_num_pages = reader.readUnsignedInt(offset + 4);
		size = reader.readUnsignedInt(offset + 8);
	}
}
