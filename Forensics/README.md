# 🔎 Forensics CTF Cheatsheet
## File Format Analysis

### 1. **Basic File Identification**
**`file`**:
   - Identifies file type based on magic numbers. If you were given a binary file or file without extension, check using `file` first.
     
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

### 6. **ELF (Executable and Linkable Format) Files**
   - **`readelf`**: Displays information about ELF files.
     ```bash
     readelf -a <filename>
     ```

   - **`objdump`**: Displays headers, sections, and disassembly of ELF files.
     ```bash
     objdump -d <filename>
     ```

## Corrupted Image Recovery

### 1. **Automated Tools**
Due to CTF time constraints, it is recommended that players use tools to automate the process. 
   - [PCRT](https://github.com/sherlly/PCRT): A Python software that can auto-fix corrupted images.
     ```
      python PCRT.py -h
      usage: PCRT.py [-h] [-q] [-y] [-v] [-m] [-n NAME] [-p PAYLOAD] [-w WAY]
                     [-d DECOMPRESS] [-i INPUT] [-f] [-o OUTPUT]
      
      optional arguments:
        -h, --help            show this help message and exit
        -q, --quiet           don't show the banner infomation
        -y, --yes             auto choose yes
        -v, --verbose         use the safe way to recover
        -m, --message         show the image information
        -n NAME, --name NAME  payload name [Default: random]
        -p PAYLOAD, --payload PAYLOAD
                              payload to hide
        -w WAY, --way WAY     payload chunk: [1]: ancillary [2]: critical
                              [Default:1]
        -d DECOMPRESS, --decompress DECOMPRESS
                              decompress zlib data file name
        -i INPUT, --input INPUT
                              Input file name (*.png) [Select from terminal]
        -f, --file            Input file name (*.png) [Select from window]
        -o OUTPUT, --output OUTPUT
                              Output repaired file name [Default: output.png]     
      ```
   - [FotoForensics](https://fotoforensics.com/): Online image recovery tool.
     
     ![image](https://github.com/user-attachments/assets/07150792-eb4d-47f4-9d0c-6a0f4d2d29b6)

### 2. **Manually Patching Corrupted Headers**
There will be certain cases where tools can't recover the image file, then we need to manually fix the image file. An easy image recovery challenge only requires the CTF players to modify the magic bytes of an image file.  

   - **Magic Bytes**: Also can refer [here](https://en.wikipedia.org/wiki/List_of_file_signatures).
     1. `.jpg`: `FF D8 FF`
     2. `.png`: `89 50 4E 47 0D 0A 1A 0A`
     3. `.bmp`: `42 4D`
     4. `.gif`: `47 49 46 38 37 61`

   - **JPG File Header**:

```
typedef struct _JFIFHeader
{
  BYTE SOI[2];          /* 00h  Start of Image Marker     FFh D8h*/
  BYTE APP0[2];         /* 02h  Application Use Marker    FFh E0h*/
  BYTE Length[2];       /* 04h  Length of APP0 Field      */
  BYTE Identifier[5];   /* 06h  "JFIF" (zero terminated) Id String 4Ah 46h 49h 46h 00h */
  BYTE Version[2];      /* 07h  JFIF Format Revision      01h 02h/ 01h 00h */
  BYTE Units;           /* 09h  Units used for Resolution */
  BYTE Xdensity[2];     /* 0Ah  Horizontal Resolution     */
  BYTE Ydensity[2];     /* 0Ch  Vertical Resolution       */
  BYTE XThumbnail;      /* 0Eh  Horizontal Pixel Count    */
  BYTE YThumbnail;      /* 0Fh  Vertical Pixel Count      */
} JFIFHEAD;
```


   - **JPEG Header Patching**:
Modify the magic bytes and compare them with any normal JPEG file.  

Corrupted file:

   ![image](https://github.com/user-attachments/assets/09d97b0d-7aae-480f-869b-fcf66b325141)

Repaired file:

![image](https://github.com/user-attachments/assets/25fb4338-5607-458f-b428-d8c306b3949a)


   - **PNG Header Patching**:
     1. Use `pngcheck` to verify file information.
     2. Ensure the `IHDR` chunk follows immediately after the PNG signature in the hex dump.
        
     

   - **Repair with a hex editor**: If only the header is corrupted, you can replace the corrupted header with a correct one from a similar working JPEG image. Use **`xxd`** to copy the first few lines (header) from a working JPEG and patch it into the corrupted file.




#### 8. **Check for Data Hiding (Steganography)**
   - **`steghide`**: Check if steganographic data was used, especially if the image appears corrupted but still has valid portions.
     ```bash
     steghide extract -sf <corrupted_image>
     ```

   - **`zsteg`**: Analyze PNG files for LSB steganography or other common hiding techniques.
     ```bash
     zsteg <corrupted_image>
     ```


#### 10. **Repair Online Tools**
   - **[JPEG-Repair Online Tool](https://www.impulseadventure.com/photo/fix-corrupt-jpeg.html)**: Offers a web-based interface to repair corrupted JPEG files.
   - **[Online PNG Tools](https://onlinepngtools.com/)**: A suite of tools to analyze and repair PNG files online.

