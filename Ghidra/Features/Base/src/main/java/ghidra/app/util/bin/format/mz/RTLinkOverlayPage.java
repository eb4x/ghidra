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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

/**
 * Represents a single RTLink/Plus overlay page: its header, relocation entries, and
 * the file region where code bytes reside.  Code bytes are not stored here; they are
 * read directly from {@link ghidra.program.database.mem.FileBytes} when creating
 * memory blocks.
 */
public class RTLinkOverlayPage {

	private final int pageIndex;
	private final long fileOffset;
	private final RTLinkPageHeader header;
	private final List<RTLinkRelocation> relocations;

	/**
	 * Constructs an overlay page by reading the header and relocations at the given
	 * file offset.
	 *
	 * @param reader    A {@link BinaryReader} for the file
	 * @param fileOffset Absolute file offset where this page starts
	 * @param pageIndex  0-based page number
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkOverlayPage(BinaryReader reader, long fileOffset, int pageIndex)
			throws IOException {
		this.pageIndex = pageIndex;
		this.fileOffset = fileOffset;

		reader.setPointerIndex(fileOffset);
		header = new RTLinkPageHeader(reader);

		relocations = new ArrayList<>();
		for (long i = 0; i < header.getRelocCount(); i++) {
			relocations.add(new RTLinkRelocation(reader));
		}
	}

	public int getPageIndex() {
		return pageIndex;
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public RTLinkPageHeader getHeader() {
		return header;
	}

	public List<RTLinkRelocation> getRelocations() {
		return relocations;
	}

	/**
	 * Returns the file offset where the code bytes begin (past the overhead area).
	 *
	 * @return code region file offset
	 */
	public long getCodeFileOffset() {
		return fileOffset + header.getOverheadSizeBytes();
	}

	/**
	 * Returns the number of code bytes in this page.
	 *
	 * @return code size in bytes
	 */
	public int getCodeSize() {
		return header.getCodeSizeBytes();
	}

	/**
	 * Returns the overlay frame size from the page header.
	 *
	 * @return frame size in bytes
	 */
	public long getFrameSize() {
		return header.getFrameSize();
	}

	/**
	 * Parses all contiguous RTLink/Plus overlay pages starting at the given file
	 * offset.  Stops when a header fails validation or the end of the file is reached.
	 *
	 * @param reader       A {@link BinaryReader} for the file
	 * @param overlayStart File offset where overlay data begins
	 * @param fileLength   Total file length
	 * @return list of parsed overlay pages (may be empty)
	 */
	public static List<RTLinkOverlayPage> parseAllPages(BinaryReader reader, long overlayStart,
			long fileLength) {
		List<RTLinkOverlayPage> pages = new ArrayList<>();
		long cursor = overlayStart;
		int pageIndex = 0;

		while (cursor + RTLinkPageHeader.HEADER_SIZE <= fileLength) {
			try {
				RTLinkOverlayPage page = new RTLinkOverlayPage(reader, cursor, pageIndex);
				if (!page.getHeader().isValid()) {
					break;
				}
				int totalSize = page.getHeader().getTotalSizeBytes();
				if (totalSize <= 0 || cursor + totalSize > fileLength) {
					break;
				}
				pages.add(page);
				cursor += totalSize;
				pageIndex++;
			}
			catch (IOException e) {
				break;
			}
		}
		return pages;
	}

	@Override
	public String toString() {
		return String.format("RTLinkOverlayPage[page=%d fileOff=0x%X codeOff=0x%X codeSize=0x%X]",
			pageIndex, fileOffset, getCodeFileOffset(), getCodeSize());
	}
}
