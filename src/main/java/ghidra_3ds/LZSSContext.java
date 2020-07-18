package ghidra_3ds;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

// adapted from ctrtool

public class LZSSContext {
	byte[] compressed;
	byte[] decompressed;

	public LZSSContext(byte[] compressed_in) {
		compressed = compressed_in;
	}
	
	public byte[] decompress() throws IOException {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(compressed), true);
		
		int compressed_size = compressed.length;
		
		int buffertopandbottom = reader.readInt(compressed.length - 8);
		int originalbottom = reader.readInt(compressed.length - 4);
		int decompressed_size = originalbottom + compressed_size;
		
		int i,j;
		int out = decompressed_size;
		int index = compressed_size - ((buffertopandbottom>>24)&0xff);
		int segment_offset;
		int segment_size;

		int control;
		int stopindex = compressed_size - (buffertopandbottom&0xFFFFFF);
		
		decompressed = new byte[decompressed_size];
		System.arraycopy(compressed, 0, decompressed, 0, compressed.length); // lmao
		
		while(index > stopindex)
		{
			control = compressed[--index];

			for(i=0; i<8; i++)
			{
				if (index <= stopindex)
					break;

				if (index <= 0)
					break;

				if (out <= 0)
					break;

				if ((control & 0x80) == 0x80)
				{
					if (index < 2)
					{
						throw new IOException("Error, compression out of bounds");
					}

					index -= 2;

					segment_offset = (compressed[index] & 0xff) | ((compressed[index+1]&0xff)<<8);

					segment_size = ((segment_offset >> 12)&15)+3;
					segment_offset &= 0x0FFF;
					segment_offset += 2;

					if (out < segment_size)
					{
						throw new IOException("Error, compression out of bounds");
					}

					for(j=0; j<segment_size; j++)
					{
						byte data;
						
						if (out+segment_offset >= decompressed_size)
						{
							throw new IOException("Error, compression out of bounds");
						}

						data  = decompressed[out+segment_offset];
						decompressed[--out] = data;
					}
				}
				else
				{
					if (out < 1)
					{
						throw new IOException("Error, compression out of bounds");
					}
					decompressed[--out] = compressed[--index];
				}

				control <<= 1;
				control = control & 0xff;
			}
		}

		return decompressed;
	}
}
