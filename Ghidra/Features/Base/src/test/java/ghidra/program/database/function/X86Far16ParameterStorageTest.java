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
package ghidra.program.database.function;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;

/**
 * Verify that the default 16-bit x86 compiler spec (x86-16.cspec) packs stack
 * parameters with 2-byte alignment.  The stack in 16-bit code is 2-byte
 * granular (every push is a word) and 16-bit compilers (e.g. Microsoft C 6.0)
 * pack stack parameters accordingly - a 4-byte {@code long} must not be padded
 * out to a 4-byte boundary.
 */
public class X86Far16ParameterStorageTest extends AbstractGenericTest {

	@Test
	public void testFarCallLongStackParameterPacking_RealMode() throws Exception {
		do16BitTest(ProgramBuilder._X86_16_REAL_MODE);
	}

	@Test
	public void testFarCallLongStackParameterPacking_ProtectedMode() throws Exception {
		do16BitTest("x86:LE:16:Protected Mode");
	}

	private void do16BitTest(String languageId) throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Test", languageId);
		builder.createMemory("Seg_0", "1000:0000", 0x1000);
		Program program = builder.getProgram();
		Function function =
			builder.createEmptyFunction("func", "1000:0100", 10, new IntegerDataType());

		Parameter a = new ParameterImpl("a", ShortDataType.dataType, program);
		Parameter b = new ParameterImpl("b", LongDataType.dataType, program);
		Parameter c = new ParameterImpl("c", ShortDataType.dataType, program);

		int txId = program.startTransaction("update function");
		try {
			// Dynamic (non-custom) storage: the __cdecl16far prototype model
			// assigns the parameter storage automatically.
			function.updateFunction("__cdecl16far",
				new ReturnParameterImpl(IntegerDataType.dataType, program),
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, a,
				b, c);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertFalse(function.hasCustomVariableStorage());

		// Expected layout for a far call (return address = IP + CS = 4 bytes,
		// so the __cdecl16far stack pentry starts at offset 0x4), with stack
		// parameters packed at 2-byte alignment:
		//
		//   Stack[0x0..0x3]  far return address
		//   Stack[0x4..0x5]  short a
		//   Stack[0x6..0x9]  long b   (2-byte aligned - NOT padded to 0x8)
		//   Stack[0xA..0xB]  short c
		Parameter[] params = function.getParameters();
		assertEquals(3, params.length);

		assertTrue(params[0].isStackVariable());
		assertEquals("short a", 0x4, params[0].getStackOffset());

		assertTrue(params[1].isStackVariable());
		assertEquals("long b", 0x6, params[1].getStackOffset());

		assertTrue(params[2].isStackVariable());
		assertEquals("short c", 0xA, params[2].getStackOffset());
	}
}
