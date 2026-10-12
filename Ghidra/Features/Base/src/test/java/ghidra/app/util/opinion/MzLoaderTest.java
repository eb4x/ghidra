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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HexFormat;

import org.junit.After;
import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Tests for {@link MzLoader}. Load tests place the image at 1000:0000; a relocated segment word
 * 0003 becomes segment 1003, whose block starts at image offset 0x30.
 */
public class MzLoaderTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final int HEADER_SIZE = 0x40;
	private static final int RELOCATION_TABLE = 0x1c;
	private static final int E_LFANEW = 0x3c;

	private Program program;

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
	}

	/**
	 * {@return an MZ file: a 0x40-byte header, then the image; each relocation is the image offset
	 * of a segment word in segment 0}
	 */
	private static byte[] mz(byte[] image, int... relocations) {
		int size = HEADER_SIZE + image.length;
		ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
		buf.putShort(0, (short) 0x5a4d); // MZ
		buf.putShort(2, (short) (size % 512)); // e_cblp
		buf.putShort(4, (short) ((size + 511) / 512)); // e_cp
		buf.putShort(6, (short) relocations.length); // e_crlc
		buf.putShort(8, (short) (HEADER_SIZE / 16)); // e_cparhdr
		buf.putShort(0x10, (short) 0x100); // e_sp
		buf.putShort(0x18, (short) RELOCATION_TABLE); // e_lfarlc
		for (int i = 0; i < relocations.length; i++) {
			buf.putShort(RELOCATION_TABLE + 4 * i, (short) relocations[i]);
		}
		buf.put(HEADER_SIZE, image);
		return buf.array();
	}

	/** {@return an MZ file with {@code header} as its image and e_lfanew pointing at it} */
	private static byte[] mzWithNewHeader(byte[] header) {
		byte[] file = mz(header);
		put(file, E_LFANEW, "40 00 00 00");
		return file;
	}

	/** Puts the space-separated hex {@code bytes} into {@code dest} at {@code offset}. */
	private static void put(byte[] dest, int offset, String bytes) {
		byte[] src = HexFormat.ofDelimiter(" ").parseHex(bytes);
		System.arraycopy(src, 0, dest, offset, src.length);
	}

	/** {@return a PE32 i386 header with no sections} */
	private static byte[] pe() {
		byte[] pe = new byte[0xf8];
		put(pe, 0x00, "50 45 00 00 4c 01"); // PE signature, Machine i386
		put(pe, 0x14, "e0 00"); // SizeOfOptionalHeader
		put(pe, 0x18, "0b 01"); // Magic: PE32
		put(pe, 0x3c, "00 02"); // FileAlignment
		put(pe, 0x74, "10"); // NumberOfRvaAndSizes
		return pe;
	}

	/** {@return an NE header whose tables are all empty, at file offset 0x40} */
	private static byte[] ne() {
		byte[] ne = new byte[0x41];
		put(ne, 0x00, "4e 45"); // NE
		put(ne, 0x04, "40 00"); // ne_enttab
		put(ne, 0x22, "40 00 40 00 40 00 40 00 40 00"); // segment to imported names tables
		put(ne, 0x2c, "80 00 00 00"); // ne_nrestab, a file offset
		return ne;
	}

	private static boolean accepts(Loader loader, byte[] file) throws IOException {
		try (ByteArrayProvider provider = new ByteArrayProvider(file)) {
			return !loader.findSupportedLoadSpecs(provider).isEmpty();
		}
	}

	/** {@return an image of {@code length} NOPs} */
	private static byte[] nops(int length) {
		byte[] image = new byte[length];
		Arrays.fill(image, (byte) 0x90);
		return image;
	}

	private void load(byte[] file) throws Exception {
		try (LoadResults<Program> results = ProgramLoader.builder()
				.source(file)
				.name("mz")
				.loaders(MzLoader.class)
				.language("x86:LE:16:Real Mode")
				.compiler("default")
				.load()) {
			program = results.getPrimaryDomainObject(this);
		}
	}

	private Address addr(String at) {
		return program.getAddressFactory().getAddress(at);
	}

	private String blockStart(String at) {
		MemoryBlock block = program.getMemory().getBlock(addr(at));
		assertNotNull("no block at " + at, block);
		return block.getStart().toString();
	}

	private long cs(String at) {
		Register cs = program.getRegister("CS");
		BigInteger value = program.getProgramContext().getValue(cs, addr(at), false);
		assertNotNull("no CS at " + at, value);
		return value.longValue();
	}

	@Test
	public void testAcceptsMz() throws IOException {
		assertTrue(accepts(new MzLoader(), mz(new byte[0x10])));
	}

	@Test
	public void testAcceptsMzWithLeHeader() throws IOException {
		byte[] le = new byte[0x40];
		put(le, 0x00, "4c 45"); // LE
		assertTrue(accepts(new MzLoader(), mzWithNewHeader(le)));
	}

	@Test
	public void testAcceptsMzWithLfanewPastEnd() throws IOException {
		byte[] file = mz(new byte[0x10]);
		put(file, E_LFANEW, "ff ff ff 00");
		assertTrue(accepts(new MzLoader(), file));
	}

	@Test
	public void testRejectsPe() throws IOException {
		byte[] file = mzWithNewHeader(pe());
		assertTrue(accepts(new PeLoader(), file));
		assertFalse(accepts(new MzLoader(), file));
	}

	@Test
	public void testRejectsNe() throws IOException {
		byte[] file = mzWithNewHeader(ne());
		assertTrue(accepts(new NeLoader(), file));
		assertFalse(accepts(new MzLoader(), file));
	}

	/** With no far call into the second segment, a FAR RETURN still ends the first one. */
	@Test
	public void testSegmentStartsAfterFarReturn() throws Exception {
		byte[] image = nops(0x46);
		put(image, 0x00, "b8 03 00"); // MOV AX,0003 (a segment reference, not a call)
		put(image, 0x03, "cb"); // RETF
		put(image, 0x34, "cb"); // 1003:0004, the first segment's last RETF
		put(image, 0x45, "cb"); // 1003:0015, past the paragraph
		load(mz(image, 0x01));
		assertEquals("1003:0005", blockStart("1003:0005"));
		assertEquals("1000:0000", blockStart("1000:0034"));
	}

	/**
	 * The first segment ends in RETF 2, not a FAR RETURN; the second segment's code starts at
	 * its lowest far CALL/JMP target.
	 */
	@Test
	public void testSegmentStartsAtLowestFarTarget() throws Exception {
		byte[] image = nops(0x50);
		put(image, 0x00, "9a 12 00 03 00"); // CALLF 0003:0012
		put(image, 0x05, "ea 04 00 03 00"); // JMPF 0003:0004
		put(image, 0x30, "ca 02 00"); // 1003:0000: RETF 2, the first segment's last instruction
		load(mz(image, 0x03, 0x08));
		assertEquals("1003:0004", blockStart("1003:0004"));
		assertEquals("1000:0000", blockStart("1000:0032"));
		assertEquals(0x1000, cs("1000:0032"));
	}

	/**
	 * A FAR RETURN before the lowest far target ends the first segment; one inside the called
	 * function does not.
	 */
	@Test
	public void testSegmentStartsAfterFarReturnBeforeFarTarget() throws Exception {
		byte[] image = nops(0x50);
		put(image, 0x00, "9a 06 00 03 00"); // CALLF 0003:0006
		put(image, 0x05, "cb"); // RETF
		put(image, 0x31, "cb"); // 1003:0001, the first segment's last RETF
		put(image, 0x39, "cb"); // 1003:0009, a RETF inside the called function
		load(mz(image, 0x03));
		assertEquals("1003:0002", blockStart("1003:0002"));
	}

	/**
	 * A far call to 1003:0000 keeps the block whole, so a FAR RETURN in its first function does
	 * not move that function to the previous block.
	 */
	@Test
	public void testFarCallToParagraphStartKeepsBlock() throws Exception {
		byte[] image = nops(0x40);
		put(image, 0x00, "9a 00 00 03 00"); // CALLF 0003:0000
		put(image, 0x05, "cb"); // RETF
		put(image, 0x2f, "cb"); // the first segment's last RETF
		put(image, 0x35, "cb"); // 1003:0005, a RETF inside the called function
		load(mz(image, 0x03));
		assertEquals("1003:0000", blockStart("1003:0005"));
		assertEquals(0x1003, cs("1003:0005"));
	}
}
