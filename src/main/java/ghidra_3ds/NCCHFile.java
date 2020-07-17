package ghidra_3ds;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

public class NCCHFile {
	NCCHHeader header;
	NCCHExheader exheader;
	ExeFS exefs;
	
	public NCCHFile(ByteProvider provider) throws IOException {
		header = new NCCHHeader(provider);
		if(header.exheader_size != 0) {
			exheader = new NCCHExheader(provider);
		}
		
		// dont care about the plain region for now, might be nice to expose it somehow for sdk strings
		// definitely dont care about logo
		NCCHRegion exefs_region = header.exefs_region;
		exefs = new ExeFS(provider, exefs_region.offset);
		
		// also dont care about romfs 
	}
}
