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
 * Parses a 16-byte RTLink/Plus overlay page header.
 *
 * <pre>
 * struct rtlink_page_header {
 *     uint16 total_paragraphs;     // total record size in 16-byte paragraphs
 *     uint16 overhead_paragraphs;  // header+relocs+padding; code starts after
 *     uint32 frame_size;           // overlay frame size in bytes
 *     uint32 reloc_count;          // number of 4-byte relocation entries
 *     uint32 reserved;             // always 0
 * };
 * </pre>
 */
public class RTLinkPageHeader implements StructConverter {

	public static final String NAME = "RTLink_Page_Header";
	public static final int HEADER_SIZE = 16;

	private int totalParagraphs;
	private int overheadParagraphs;
	private long frameSize;
	private long relocCount;
	private long reserved;

	/**
	 * Constructs a new RTLink/Plus page header
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of the header
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkPageHeader(BinaryReader reader) throws IOException {
		totalParagraphs = Short.toUnsignedInt(reader.readNextShort());
		overheadParagraphs = Short.toUnsignedInt(reader.readNextShort());
		frameSize = Integer.toUnsignedLong(reader.readNextInt());
		relocCount = Integer.toUnsignedLong(reader.readNextInt());
		reserved = Integer.toUnsignedLong(reader.readNextInt());
	}

	public int getTotalParagraphs() {
		return totalParagraphs;
	}

	public int getOverheadParagraphs() {
		return overheadParagraphs;
	}

	public long getFrameSize() {
		return frameSize;
	}

	public long getRelocCount() {
		return relocCount;
	}

	public long getReserved() {
		return reserved;
	}

	public int getTotalSizeBytes() {
		return totalParagraphs * 16;
	}

	public int getOverheadSizeBytes() {
		return overheadParagraphs * 16;
	}

	public int getCodeSizeBytes() {
		return getTotalSizeBytes() - getOverheadSizeBytes();
	}

	/**
	 * Checks whether this looks like a valid RTLink/Plus page header
	 *
	 * @return true if the header fields are structurally consistent
	 */
	public boolean isValid() {
		if (totalParagraphs <= 0) {
			return false;
		}
		if (overheadParagraphs <= 0 || overheadParagraphs > totalParagraphs) {
			return false;
		}
		if (frameSize <= 0 || frameSize > 0x10000) {
			return false;
		}
		if (reserved != 0) {
			return false;
		}
		if (HEADER_SIZE + relocCount * 4 > (long) overheadParagraphs * 16) {
			return false;
		}
		return true;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "total_paragraphs", "Total record size in 16-byte paragraphs");
		struct.add(WORD, "overhead_paragraphs", "Header+relocs+padding paragraphs");
		struct.add(DWORD, "frame_size", "Overlay frame size in bytes");
		struct.add(DWORD, "reloc_count", "Number of 4-byte relocation entries");
		struct.add(DWORD, "reserved", "Reserved (always 0)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format(
			"RTLinkPageHeader[total=%d overhead=%d frame=0x%X relocs=%d]",
			totalParagraphs, overheadParagraphs, frameSize, relocCount);
	}
}
