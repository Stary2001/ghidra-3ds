package ghidra_3ds;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class ExeFSFile {
	String name;
	long offset;
	long size;
	byte[] sha256;

	public ExeFSFile(ByteProvider provider, long header_offset) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		name = reader.readAsciiString(header_offset, 8);
		offset = header_offset + 0x200 + reader.readUnsignedInt(header_offset + 0x8);
		size = reader.readUnsignedInt(header_offset + 0xc);
	}
}
