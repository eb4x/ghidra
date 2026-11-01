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
package ghidra.app.cmd.analysis;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * The contiguous-functions pass of {@link SharedReturnAnalysisCmd} makes a function of the
 * target of a jump across another function's entry when the target is a tail, entered only at
 * its start, but not when the target's code jumps back into the function that reached it.
 */
public class SharedReturnAnalysisCmdTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("SharedReturnTest", ProgramBuilder._X86);
		builder.createMemory(".text", "0x1000", 0x100);
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	/**
	 * An error exit that A reaches with a Jcc and B with a JMP across A's entry is a tail they
	 * share: it becomes a function, and B's jump a call-return.
	 */
	@Test
	public void testSharedExitBecomesFunction() throws Exception {
		// B: TEST EAX,EAX; JMP 0x1017
		builder.setBytes("0x1000", "85c0e910000000");
		// A: TEST EAX,EAX; JZ 0x1017; XOR EAX,EAX; RET
		//    0x1017: MOV EAX,-1; RET
		builder.setBytes("0x1010", "85c0740331c0c3b8ffffffffc3");
		build("0x1010", 13, "0x1000", 7);

		analyze();

		assertNotNull("Shared exit not made a function", functionAt("0x1017"));
	}

	/**
	 * A block placed before A's entry, which A jumps back to and which jumps back into A, is
	 * A's own code: it doesn't become a function.
	 */
	@Test
	public void testBlockRejoiningItsFunctionStaysInIt() throws Exception {
		// 0x1000: INC EAX; JMP 0x1016
		builder.setBytes("0x1000", "40eb13");
		// A: TEST EAX,EAX; JNZ 0x1016; JMP 0x1000
		//    0x1016: DEC EAX; RET
		builder.setBytes("0x1010", "85c07502ebea48c3");
		builder.disassemble("0x1000", 3);
		build("0x1010", 8, null, 0);

		analyze();

		assertNull("Block split from its function", functionAt("0x1000"));
		assertTrue("Block left A", functionAt("0x1010").getBody().contains(addr("0x1000")));
	}

	/**
	 * A block that A reaches with a Jcc and B with a JMP across A's entry is not a shared tail
	 * when it jumps back into A: it stays in A.
	 */
	@Test
	public void testBlockRejoiningTheBranchingFunctionIsNoTail() throws Exception {
		// B: TEST EAX,EAX; JMP 0x1018
		builder.setBytes("0x1000", "85c0e911000000");
		// A: TEST EAX,EAX; JNZ 0x1018; XOR EAX,EAX
		//    0x1016: DEC EAX; RET
		//    0x1018: INC EAX; JMP 0x1016
		builder.setBytes("0x1010", "85c0750431c048c340ebfb");
		build("0x1010", 11, "0x1000", 7);

		analyze();

		assertNull("Block split from its function", functionAt("0x1018"));
		assertTrue("Block left A", functionAt("0x1010").getBody().contains(addr("0x1018")));
	}

	/**
	 * A routine before A's entry that A jumps to, and that returns through the RET at the end of
	 * the function C before it, shares only that return: it becomes a function.
	 */
	@Test
	public void testRoutineSharingAReturnBecomesFunction() throws Exception {
		// C: XOR EAX,EAX; RET
		builder.setBytes("0x1000", "31c0c3");
		// 0x1003: TEST EAX,EAX; JNZ 0x1002; MOV EAX,1; RET
		builder.setBytes("0x1003", "85c075fbb801000000c3");
		// A: TEST EAX,EAX; JMP 0x1003
		builder.setBytes("0x1010", "85c0e9ecffffff");
		builder.disassemble("0x1000", 3);
		builder.createFunction("0x1000");
		builder.disassemble("0x1003", 10);
		build("0x1010", 7, null, 0);

		analyze();

		assertNotNull("Routine not made a function", functionAt("0x1003"));
	}

	/**
	 * Two exit routines that run into each other, as a runtime library's do, reached by A and B
	 * with a JMP each: both become functions, though the second enters the first's code.
	 */
	@Test
	public void testTailsRunningIntoEachOtherBecomeFunctions() throws Exception {
		// T1: XOR EAX,EAX
		//     0x1002: POP EBP; RET
		// T2: JNC 0x1002; DEC EAX; POP EBP; RET
		builder.setBytes("0x1000", "31c05dc373fc485dc3");
		// A: TEST EAX,EAX; JMP 0x1000
		builder.setBytes("0x1010", "85c0e9e9ffffff");
		// B: TEST EAX,EAX; JMP 0x1004
		builder.setBytes("0x1020", "85c0e9ddffffff");
		builder.disassemble("0x1000", 9);
		build("0x1010", 7, "0x1020", 7);

		analyze();

		assertNotNull("First exit not made a function", functionAt("0x1000"));
		assertNotNull("Second exit not made a function", functionAt("0x1004"));
	}

	/**
	 * Disassemble and create A, then B if given, so that B's jump into A doesn't pull A's code
	 * into B's body.
	 */
	private void build(String a, int aLength, String b, int bLength) throws Exception {
		builder.disassemble(a, aLength);
		builder.createFunction(a);
		if (b != null) {
			builder.disassemble(b, bLength);
			builder.createFunction(b);
		}
		program = builder.getProgram();
	}

	/** Run the pass over the whole program, then the function creation it schedules. */
	private void analyze() {
		int tx = program.startTransaction("Shared Return");
		try {
			new SharedReturnAnalysisCmd(program.getMemory(), true, false).applyTo(program,
				TaskMonitor.DUMMY);
			AutoAnalysisManager.getAnalysisManager(program).startAnalysis(TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Function functionAt(String address) {
		return program.getFunctionManager().getFunctionAt(addr(address));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
