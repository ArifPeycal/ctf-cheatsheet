# 🔎 Forensics CTF Cheatsheet
## File Format Analysis

### 1. **Basic File Identification**
**`file`**:
   - Identifies file type based on magic numbers.
     
     ```bash
     file <filename>
     ```

**`xxd`** / **`hexdump`**:
   - View the raw bytes of a file in hexadecimal.

     ```bash
     xxd <filename>
     hexdump -C <filename>
     ```

**`strings`**:

   - Extract human-readable strings from a file. Combine with `grep` or `findstr` to get the flag directly.
     
     ```bash
     strings <filename> | grep <strings>
     ```

### 2. **Metadata Extraction**
**`exiftool`**:

   - Extracts metadata from various file types (images, PDFs, etc.).
     
     ```bash
     exiftool <filename>
     ```

**`binwalk`**:

   - Scans files for embedded data and file systems, can extract files.
     
     ```bash
     binwalk -e <filename>
     ```

**`foremost`**:
   - Carve out hidden files based on headers and footers.

     ```bash
     foremost -i <filename> -o <output_directory>
     ```

### 3. **Compression and Archives**
**`tar`, `zip`, `unzip`, `7z`, `gzip`, etc.**:

   - For working with compressed files and archives.
     - Example: `tar -xvf <file.tar>` to extract a `.tar` file.
     - Example: `unzip <file.zip>` to extract a `.zip` file.

### 4. **PDF Files**
**`pdfinfo`**:
   - Extracts metadata from PDFs.
     
     ```bash
     pdfinfo <filename.pdf>
     ```

**`pdf-parser`**:
   - For deeper PDF structure analysis.
     
     ```bash
     python pdf-parser.py <filename.pdf>
     ```

### 5. **Image files**

**`pngcheck`**:
   - Verifies the integrity of PNG images and can show metadata.
     
     ```bash
     pngcheck -v <filename.png>
     ```


### 6. **PE (Portable Executable) Files**
**`pefile`**:
   - Python module for parsing and analyzing PE files.
     
     ```python
     import pefile
     pe = pefile.PE('malware.exe')
     ```

**`exiftool`**:
   - Can also extract metadata from executable files.
     
     ```bash
     exiftool <filename.exe>
     ```


### 7. **ELF (Executable and Linkable Format) Files**
   - **`readelf`**: Displays information about ELF files.
     ```bash
     readelf -a <filename>
     ```

   - **`objdump`**: Displays headers, sections, and disassembly of ELF files.
     ```bash
     objdump -d <filename>
     ```
