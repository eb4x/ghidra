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
package ghidra.app.plugin.processors.sleigh;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

/** Flow targets of near rel16 branches, which go to CS:((IP_next + rel16) mod 0x10000). */
public class X86Rel16TargetTest extends AbstractGenericTest {

	private static final String REAL = ProgramBuilder._X86_16_REAL_MODE;
	private static final String PROTECTED = "x86:LE:16:Protected Mode";

	private ProgramBuilder builder;

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	private long target(String language, String at, String bytes) throws Exception {
		return target(language, at, bytes, null);
	}

	/**
	 * {@return the flow target of {@code bytes} disassembled at {@code at} without following flows,
	 * with {@code segment} as the code segment unless it is null}
	 */
	private long target(String language, String at, String bytes, Integer segment)
			throws Exception {
		builder = new ProgramBuilder("Rel16", language);
		builder.createMemory("code", at, 0x10);
		builder.setBytes(at, bytes);
		if (segment != null) {
			setCodeSegment(at, segment);
		}
		builder.disassemble(at, bytes.split(" ").length, false);
		Instruction instr = builder.getProgram().getListing().getInstructionAt(builder.addr(at));
		assertNotNull("no instruction at " + at, instr);
		Address[] flows = instr.getFlows();
		assertEquals(1, flows.length);
		return flows[0].getOffset();
	}

	/** Sets CS and cseg at {@code at}, as MzLoader does. */
	private void setCodeSegment(String at, int segment) throws Exception {
		builder.setRegisterValue("CS", at, at, segment);
		builder.setRegisterValue("cseg", at, at, segment);
	}

	/** Unaligned segment, the branch crosses a linear 64K page, IP does not wrap (#981). */
	@Test
	public void testRealModeUnalignedSegmentCrossingPage() throws Exception {
		// 1d1d:2f5b JMP -> 1d1d:1515
		assertEquals(0x1E6E5L, target(REAL, "1d1d:2f5b", "e9 b7 e5", 0x1d1d));
	}

	/** Unaligned segment, IP wraps (the #4074 example). */
	@Test
	public void testRealModeUnalignedSegmentWrap() throws Exception {
		// 01ed:0003 CALL -> 01ed:e4ad
		assertEquals(0x1037DL, target(REAL, "01ed:0003", "e8 a7 e4", 0x01ed));
	}

	/** As above for a conditional jump, which reaches rel16 through jccRel16. */
	@Test
	public void testRealModeUnalignedSegmentWrapJcc() throws Exception {
		// 01ed:0003 JZ -> 01ed:e4ad
		assertEquals(0x1037DL, target(REAL, "01ed:0003", "0f 84 a6 e4", 0x01ed));
	}

	/** Unaligned segment, the instruction ends at seg:FFFF, so inst_next is past the segment. */
	@Test
	public void testRealModeUnalignedSegmentEndWrap() throws Exception {
		// 01ed:fffd JMP -> 01ed:0010
		assertEquals(0x1EE0L, target(REAL, "01ed:fffd", "e9 10 00", 0x01ed));
	}

	/** 64K-aligned segment, IP wraps: a span over 32K, as in small-model code at 1000:0000. */
	@Test
	public void testRealModeAlignedSegmentWrap() throws Exception {
		// 1000:1000 CALL -> 1000:f000
		assertEquals(0x1F000L, target(REAL, "1000:1000", "e8 fd df", 0x1000));
	}

	/** Segment 0, IP wraps, no code segment set: the page is exact (the #981 report). */
	@Test
	public void testRealModeSegmentZeroWrap() throws Exception {
		// 0000:1ee6 CALL -> 0000:cd87
		assertEquals(0xCD87L, target(REAL, "0000:1ee6", "e8 9e ae"));
	}

	/** Without a code segment the target stays in the instruction's 64K page. */
	@Test
	public void testRealModeWithoutCodeSegment() throws Exception {
		// 1d1d:2f5b JMP -> linear 0x2e6e5, wrapped in page 0x20000
		assertEquals(0x2E6E5L, target(REAL, "1d1d:2f5b", "e9 b7 e5"));
	}

	/**
	 * Without a code segment, an instruction ending on a page boundary wraps in its own page, as
	 * in the 64K-aligned segment the page formula assumes.
	 */
	@Test
	public void testRealModeWithoutCodeSegmentAtPageEnd() throws Exception {
		// 1000:fffd JMP -> 1000:0010 if the segment is 1000
		assertEquals(0x10010L, target(REAL, "1000:fffd", "e9 10 00"));
	}

	/** Protected mode puts every selector on a 64K page, so a wrap stays in the segment. */
	@Test
	public void testProtectedModeWrap() throws Exception {
		// 1000:1000 CALL -> 1000:f000
		assertEquals(0x1000F000L, target(PROTECTED, "1000:1000", "e8 fd df"));
	}

	/** 32-bit code has protectedMode=0 too and keeps the page formula (EIP is truncated, #7418). */
	@Test
	public void testOperandSizePrefixIn32BitCode() throws Exception {
		// 0040fff0 JMP -> 00400004
		assertEquals(0x00400004L, target(ProgramBuilder._X86, "0040fff0", "66 e9 10 00"));
	}

	/** The assembler encodes a rel16 that reaches its target in an unaligned code segment. */
	@Test
	public void testAssembleRealModeUnalignedSegmentWrap() throws Exception {
		// 01ed:0003 CALL -> 01ed:e4ad
		builder = new ProgramBuilder("Rel16", REAL);
		builder.createMemory("code", "01ed:0003", 0x10);
		setCodeSegment("01ed:0003", 0x01ed);
		Address at = builder.addr("01ed:0003");
		Assembler asm = Assemblers.getAssembler(builder.getProgram());
		// assembleLine(at, line) would ignore the context at the address
		byte[] bytes = asm.assembleLine(at, "CALL 0x1037d", asm.getContextAt(at).fillMask());
		assertArrayEquals(new byte[] { (byte) 0xe8, (byte) 0xa7, (byte) 0xe4 }, bytes);
	}
}
