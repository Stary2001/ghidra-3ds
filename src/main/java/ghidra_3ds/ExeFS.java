package ghidra_3ds;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.ByteProvider;

public class ExeFS {
	ExeFSFile[] files;

	public ExeFS(ByteProvider provider, long offset) throws IOException {
		ArrayList<ExeFSFile> tempFiles = new ArrayList<ExeFSFile>();
		
		for(int i = 0; i < 10; i++) {
			ExeFSFile e = new ExeFSFile(provider, offset + i*0x10);
			if(e.name.isEmpty()) break; // done
			tempFiles.add(e);
		}

		for(int i = 0; i < tempFiles.size(); i++) {
			tempFiles.get(i).sha256 = provider.readBytes(offset + 0x1e0 - i*0x20, 0x20);
		}
		
		files = tempFiles.toArray(new ExeFSFile[0]);
	}
}
