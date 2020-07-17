package ghidra_3ds;

public class NCCHRegion {
	public NCCHRegion(long offset, long size) {
		this.offset = offset*0x200;
		this.size = size*0x200;
	}
	long offset;
	long size;
}
