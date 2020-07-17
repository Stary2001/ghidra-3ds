package ghidra_3ds;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class NCCHExheader {
	String title;
	byte flags;
	int remaster_version;
	CodeSetInfo text_section;
	CodeSetInfo rodata_section;
	CodeSetInfo data_section;
	long stack_size;
	long bss_size;
	
	long savedata_size;
	long jump_id;
	
	public NCCHExheader(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		title = reader.readAsciiString(0x200, 8);
		flags = reader.readByte(0x20d);
		remaster_version = reader.readUnsignedShort(0x20e);
		
		text_section = new CodeSetInfo(reader, 0x210);
		stack_size = reader.readUnsignedInt(0x21c);
		rodata_section = new CodeSetInfo(reader, 0x220);
		// 4 bytes reserved
		data_section = new CodeSetInfo(reader, 0x230);
		bss_size = reader.readUnsignedInt(0x23c);
		
		// dependency list
		for(int i = 0; i < 48; i++) {
			// TODO: blah
		}

		// SystemInfo
		savedata_size = reader.readLong(0x3c0);
		jump_id = reader.readLong(0x3c8);
		
		// TODO: read aci
		// TODO: aci sig
		// TODO: read key
		// TODO: aci limitations
	}
}
