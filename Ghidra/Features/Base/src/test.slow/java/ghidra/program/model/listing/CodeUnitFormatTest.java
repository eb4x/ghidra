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
package ghidra.program.model.listing;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;

/**
 * Tests that {@link CodeUnitFormat} renders operand separators the way
 * {@link Instruction#toString()} does, including the separator which follows the last operand.
 */
public class CodeUnitFormatTest extends AbstractGenericTest {

	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		// RISC-V brackets the address operand of its atomics, so the ")" of "(rs1)" is the
		// separator which follows the last operand.
		builder = new ProgramBuilder("codeUnitFormat", "RISCV:LE:64:default");
		builder.createMemory(".text", "0x0", 0x100);
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testSeparatorAfterLastOperand() throws Exception {
		Instruction instruction = disassemble("0x0", "2f 25 b6 00"); // amoadd.w a0,a1,(a2)

		String representation = CodeUnitFormat.DEFAULT.getRepresentationString(instruction);
		assertTrue("separator after the last operand was dropped: " + representation,
			representation.endsWith(")"));
		assertEquals(instruction.toString(), representation);
	}

	@Test
	public void testSeparatorsBetweenOperands() throws Exception {
		Instruction instruction = disassemble("0x0", "33 85 c5 00"); // add a0,a1,a2

		assertEquals(instruction.toString(),
			CodeUnitFormat.DEFAULT.getRepresentationString(instruction));
	}

	private Instruction disassemble(String address, String bytes) throws Exception {
		builder.setBytes(address, bytes, true);
		Instruction instruction =
			builder.getProgram().getListing().getInstructionAt(builder.addr(address));
		assertNotNull("failed to disassemble at " + address, instruction);
		return instruction;
	}
}
