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
package ghidra.app.util.bin.format.mz;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A single 4-byte RTLink/Plus overlay relocation entry.
 *
 * <pre>
 * uint16 offset;    // offset within the overlay code to patch
 * uint16 seg_index; // segment index (0 = data segment)
 * </pre>
 */
public class RTLinkRelocation implements StructConverter {

	public static final String NAME = "RTLink_Relocation";

	private int offset;
	private int segIndex;

	/**
	 * Constructs a new RTLink/Plus relocation entry
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of the entry
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkRelocation(BinaryReader reader) throws IOException {
		offset = Short.toUnsignedInt(reader.readNextShort());
		segIndex = Short.toUnsignedInt(reader.readNextShort());
	}

	/**
	 * Gets the offset within the overlay code where the fixup is applied
	 *
	 * @return The offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Gets the segment index indicating what type of segment reference this is.
	 * Index 0 typically refers to the data segment.
	 *
	 * @return The segment index
	 */
	public int getSegmentIndex() {
		return segIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "offset", "Offset within overlay code to patch");
		struct.add(WORD, "seg_index", "Segment index (0 = data segment)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format("off=%04x segidx=%04x", offset, segIndex);
	}
}
