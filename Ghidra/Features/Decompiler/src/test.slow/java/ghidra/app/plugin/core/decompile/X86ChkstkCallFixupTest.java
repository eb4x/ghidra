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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.disassembler.CallFixupAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Microsoft C's 16-bit stack probe returns with SP lowered by AX. Without the x86-16 call
 * fixup the decompiler keeps SP at the frame pointer, so the pushes for later calls land on
 * the locals.
 */
public class X86ChkstkCallFixupTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramBuilder builder;
	private Program program;
	private DecompInterface decompiler;

	@After
	public void tearDown() {
		if (decompiler != null) {
			decompiler.dispose();
		}
		if (builder != null) {
			builder.dispose();
		}
	}

	/**
	 * f at 1000:0000 calls the probe (named {@code probeName}) at 1000:0100 by CALLF, stores
	 * 0x1234 in the local at BP-4, passes 0x77 to g at 1000:0200, and returns the local.
	 */
	private Function load(String probeName) throws Exception {
		builder = new ProgramBuilder("chkstk", ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("code", "1000:0000", 0x300);
		// PUSH BP; MOV BP,SP; MOV AX,0x10; CALLF 1000:0100; MOV word [BP-4],0x1234;
		// MOV AX,0x77; PUSH AX; CALLF 1000:0200; ADD SP,2; MOV AX,[BP-4];
		// MOV SP,BP; POP BP; RETF
		builder.setBytes("1000:0000", "55 8b ec b8 10 00 9a 00 01 00 10 c7 46 fc 34 12 " +
			"b8 77 00 50 9a 00 02 00 10 83 c4 02 8b 46 fc 8b e5 5d cb");
		builder.setBytes("1000:0100", "cb");
		builder.setBytes("1000:0200", "cb");
		builder.disassemble("1000:0000", 0x23, false);
		builder.disassemble("1000:0100", 1, false);
		builder.disassemble("1000:0200", 1, false);
		builder.createFunction("1000:0000");
		builder.createFunction("1000:0100");
		builder.createFunction("1000:0200");
		program = builder.getProgram();
		Function f = functionAt("1000:0000");
		Function probe = functionAt("1000:0100");
		Function g = functionAt("1000:0200");
		assertNotNull(probe);
		assertNotNull(g);

		int tx = program.startTransaction("setup");
		try {
			probe.setName(probeName, SourceType.USER_DEFINED);
			g.setCallingConvention("__cdecl16far");
			new CallFixupAnalyzer().added(program,
				program.getMemory().getLoadedAndInitializedAddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		decompiler = new DecompInterface();
		decompiler.openProgram(program);
		return f;
	}

	private String decompile(Function f) {
		DecompileResults results = decompiler.decompileFunction(f,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		assertTrue(results.getErrorMessage(), results.decompileCompleted());
		return results.getDecompiledFunction().getC();
	}

	private Function functionAt(String at) {
		Address address = program.getAddressFactory().getAddress(at);
		return program.getFunctionManager().getFunctionAt(address);
	}

	private Function probe() {
		return functionAt("1000:0100");
	}

	@Test
	public void testChkstkLowersStackPointer() throws Exception {
		Function f = load("_chkstk");
		assertEquals("chkstk16far", probe().getCallFixup());
		String c = decompile(f);
		assertTrue(c, c.contains("return 0x1234;"));
	}

	@Test
	public void testFarProbeByMsc7Name() throws Exception {
		load("__aFchkstk");
		assertEquals("chkstk16far", probe().getCallFixup());
	}

	@Test
	public void testNearProbeByMsc7Name() throws Exception {
		load("__aNchkstk");
		assertEquals("chkstk16near", probe().getCallFixup());
	}
}
