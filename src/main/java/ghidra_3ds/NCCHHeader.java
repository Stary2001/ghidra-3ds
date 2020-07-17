package ghidra_3ds;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class NCCHHeader {
	byte[] signature;
	String magic;
	long content_size;
	String maker_code;
	byte[] partition_id;
	int version;
	long program_id;
	String product_code;
	byte[] logo_sha256;
	byte[] exheader_sha256;
	long exheader_size;
	byte[] flags;

	NCCHRegion plain_region;
	NCCHRegion logo_region;
	NCCHRegion exefs_region;
	long exefs_hash_region_size;
	NCCHRegion romfs_region;
	long romfs_hash_region_size;
	byte[] exefs_superblock_sha256;
	byte[] romfs_superblock_sha256;
	
	public NCCHHeader(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		signature = reader.readByteArray(0, 0x100);
		magic = reader.readAsciiString(0x100, 4);
		content_size = reader.readUnsignedInt(0x104);
		content_size *= 0x200; // media units

		partition_id = reader.readByteArray(0x108, 8);
		maker_code = reader.readAsciiString(0x110, 2);
		version = reader.readUnsignedShort(0x112);
		// skip  0x114
		program_id = reader.readLong(0x118);
		// 16 bytes reserved
		logo_sha256 = reader.readByteArray(0x130, 0x20);
		product_code = reader.readAsciiString(0x150, 0x10);
		exheader_sha256 = reader.readByteArray(0x160, 0x20);
		exheader_size = reader.readUnsignedInt(0x180);
		// 4 bytes reserved
		flags = reader.readByteArray(0x188, 8);
		
		plain_region = new NCCHRegion(reader.readUnsignedInt(0x190), reader.readUnsignedInt(0x194));
		logo_region = new NCCHRegion(reader.readUnsignedInt(0x198), reader.readUnsignedInt(0x19c));
		exefs_region = new NCCHRegion(reader.readUnsignedInt(0x1a0), reader.readUnsignedInt(0x1a4));
		exefs_hash_region_size = reader.readUnsignedInt(0x1a8);
		exefs_hash_region_size *= 0x200; // media units
		
		// 4 bytes reserved
		romfs_region = new NCCHRegion(reader.readUnsignedInt(0x1b0), reader.readUnsignedInt(0x1b4));
		romfs_hash_region_size = reader.readUnsignedInt(0x1b8);
		romfs_hash_region_size *= 0x200; // media units
		
		// 4 bytes reserved
		exefs_superblock_sha256 = reader.readByteArray(0x1c0, 0x20);
		romfs_superblock_sha256 = reader.readByteArray(0x1e0, 0x20);
	}
}
