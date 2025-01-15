#!/usr/bin/env node

/**
 * download-chrome-extension.js
 *
 * 1) Downloads a Chrome extension CRX.
 * 2) Extracts the extension if CRX v2 or v3/v4 (skipping the CRX header).
 * 3) Parses the ZIP via the central directory
 *
 */

const fs = require("fs");
const https = require("https");
const path = require("path");
const url = require("url");
const zlib = require("zlib");

// ---------------------------------------------------------------------
// 1. Get the extension ID from CLI
// ---------------------------------------------------------------------
const extensionId = process.argv[2];
if (!extensionId || extensionId.length !== 32) {
  console.error("Usage: node download-chrome-extension.js <EXTENSION_ID>");
  console.error("Please provide a valid 32-character extension ID.");
  process.exit(1);
}

// ---------------------------------------------------------------------
// 2. Build the CRX download URL
// ---------------------------------------------------------------------
const downloadUrl =
  "https://clients2.google.com/service/update2/crx" +
  "?response=redirect" +
  "&prod=chrome" +
  "&prodversion=9999" +
  "&acceptformat=crx2,crx3" +
  `&x=id%3D${extensionId}%26uc`;

console.log("Requesting:", downloadUrl);

// ---------------------------------------------------------------------
// 3. Fetch the CRX & extract
// ---------------------------------------------------------------------
(async function main() {
  try {
    const crxBuffer = await fetchUrl(downloadUrl);
    console.log("Got CRX data!", crxBuffer.length, "bytes");

    // Write raw CRX to disk
    fs.writeFileSync("debug.crx", crxBuffer);
    console.log("Saved debug.crx to disk");

    // Attempt to parse & extract
    try {
      extractCrxToFolder(crxBuffer, extensionId);
      console.log(`Extraction complete! See folder: ./${extensionId}`);
    } catch (err) {
      console.error("Extraction failed:", err.message);
    }
  } catch (err) {
    console.error("Failed to download CRX:", err.message);
    process.exit(1);
  }
})();

// ---------------------------------------------------------------------
// fetchUrl: minimal GET + redirect handling
// ---------------------------------------------------------------------
function fetchUrl(
  targetUrl,
  options = {},
  redirectCount = 0,
  maxRedirects = 10,
) {
  return new Promise((resolve, reject) => {
    if (redirectCount > maxRedirects) {
      return reject(new Error("Too many redirects"));
    }

    const req = https.get(targetUrl, options, (res) => {
      const { statusCode, headers } = res;

      // Follow 3xx
      if (
        (statusCode === 301 ||
          statusCode === 302 ||
          statusCode === 303 ||
          statusCode === 307 ||
          statusCode === 308) &&
        headers.location
      ) {
        const newUrl = url.resolve(targetUrl, headers.location);
        res.resume(); // discard body
        return resolve(
          fetchUrl(newUrl, options, redirectCount + 1, maxRedirects),
        );
      }

      if (statusCode !== 200) {
        res.resume();
        return reject(
          new Error(`Request failed with status code ${statusCode}`),
        );
      }

      // statusCode == 200 => read data
      const dataChunks = [];
      res.on("data", (chunk) => dataChunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(dataChunks)));
    });

    req.on("error", (err) => reject(err));
  });
}

// ---------------------------------------------------------------------
// extractCrxToFolder
//   1) Checks "Cr24" magic
//   2) Reads version (2 or 3/4) to find the ZIP start
//   3) Uses parseZipCentralDirectory() to extract files properly
// ---------------------------------------------------------------------
function extractCrxToFolder(crxBuffer, outFolder) {
  // Must start with "Cr24"
  if (crxBuffer.toString("utf8", 0, 4) !== "Cr24") {
    throw new Error("Not a valid CRX file (missing Cr24 magic).");
  }

  const version = crxBuffer.readUInt32LE(4);
  let zipStartOffset = 0;
  if (version === 2) {
    // CRX v2 header:
    //   0..3:   'Cr24'
    //   4..7:   version (2)
    //   8..11:  pubKeyLen
    //   12..15: sigLen
    //   Then pubKey + sig => ZIP
    const pkLen = crxBuffer.readUInt32LE(8);
    const sigLen = crxBuffer.readUInt32LE(12);
    zipStartOffset = 16 + pkLen + sigLen;
  } else if (version === 3 || version === 4) {
    // CRX v3+:
    //   0..3:   'Cr24'
    //   4..7:   version (3 or 4)
    //   8..11:  headerSize
    //   Then a CRX3/4 signature header (protobuf/cbor) => ZIP
    const headerSize = crxBuffer.readUInt32LE(8);
    zipStartOffset = 12 + headerSize;
  } else {
    throw new Error(
      `Unsupported CRX version (${version}). Only v2, v3, or v4 are supported.`,
    );
  }

  if (zipStartOffset >= crxBuffer.length) {
    throw new Error("Malformed CRX: header size exceeds file length.");
  }

  // This is the ZIP data
  const zipBuffer = crxBuffer.slice(zipStartOffset);

  // Parse that ZIP via the central directory approach
  parseZipCentralDirectory(zipBuffer, outFolder);
}

// ---------------------------------------------------------------------
// parseZipCentralDirectory(buffer, outFolder)
//   1) Finds the End of Central Directory (EOCD) record (0x06054b50).
//   2) Reads the central directory, which contains file metadata
//      (name, size, offset to local header, etc.).
//   3) For each file, we locate its local header & compressed data
//      and decompress it into outFolder.
//
//   This approach handles data descriptors (bit 3) and avoids
//   the "unexpected end of file" error that arises if we rely
//   solely on local headers.
// ---------------------------------------------------------------------
function parseZipCentralDirectory(zipBuffer, outFolder) {
  // 1) Find the EOCD record by searching from the end.
  //    EOCD signature = 0x06054b50.
  //    The maximum comment length is 65535, so we only need to search
  //    that far from the end.
  const eocdSig = 0x06054b50;
  let eocdPos = -1;
  const minPos = Math.max(0, zipBuffer.length - 65557); // 65535 + 22 bytes for EOCD
  for (let i = zipBuffer.length - 4; i >= minPos; i--) {
    if (zipBuffer.readUInt32LE(i) === eocdSig) {
      eocdPos = i;
      break;
    }
  }
  if (eocdPos < 0) {
    throw new Error("Could not find End of Central Directory (EOCD) in ZIP.");
  }

  // EOCD structure (without ZIP64):
  //    0..3   - signature (0x06054b50)
  //    4..5   - disk number
  //    6..7   - disk where central directory starts
  //    8..9   - number of central dir records on this disk
  //    10..11 - total number of central dir records
  //    12..15 - size of central directory (bytes)
  //    16..19 - offset of start of central directory
  //    20..21 - comment length (n)
  //    n bytes - comment
  const totalCD = zipBuffer.readUInt16LE(eocdPos + 10);
  const cdSize = zipBuffer.readUInt32LE(eocdPos + 12);
  const cdOffset = zipBuffer.readUInt32LE(eocdPos + 16);

  // Basic sanity checks
  if (cdOffset + cdSize > zipBuffer.length) {
    throw new Error("Central directory offset/size out of range.");
  }

  // 2) Parse each central directory record
  const files = [];
  let ptr = cdOffset;
  for (let i = 0; i < totalCD; i++) {
    // Each central dir file header starts with 0x02014b50
    const sig = zipBuffer.readUInt32LE(ptr);
    if (sig !== 0x02014b50) {
      throw new Error(`Central directory signature mismatch at ${ptr}`);
    }
    ptr += 4;

    // Structure of central directory file header:
    //  0..1   version made by
    //  2..3   version needed to extract
    //  4..5   general purpose bit flag
    //  6..7   compression method
    //  8..9   last mod file time
    //  10..11 last mod file date
    //  12..15 crc-32
    //  16..19 compressed size
    //  20..23 uncompressed size
    //  24..25 filename length (fLen)
    //  26..27 extra field length (xLen)
    //  28..29 file comment length (cLen)
    //  30..31 disk number start
    //  32..33 internal file attributes
    //  34..37 external file attributes
    //  38..41 relative offset of local header
    //  Then we have fLen bytes of filename, xLen bytes of extra, cLen bytes of comment
    /* const verMade   = */ zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const verNeed = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const flags = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const method = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    /* const modTime = */ zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    /* const modDate = */ zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const crc32 = zipBuffer.readUInt32LE(ptr);
    ptr += 4;
    const compSize = zipBuffer.readUInt32LE(ptr);
    ptr += 4;
    const unCompSize = zipBuffer.readUInt32LE(ptr);
    ptr += 4;
    const fLen = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const xLen = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    const cLen = zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    /* const diskNo  = */ zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    /* const intAttr= */ zipBuffer.readUInt16LE(ptr);
    ptr += 2;
    /* const extAttr= */ zipBuffer.readUInt32LE(ptr);
    ptr += 4;
    const localHeaderOffset = zipBuffer.readUInt32LE(ptr);
    ptr += 4;

    const filename = zipBuffer.toString("utf8", ptr, ptr + fLen);
    ptr += fLen;
    ptr += xLen; // skip extra
    ptr += cLen; // skip comment

    files.push({
      filename,
      method,
      compSize,
      unCompSize,
      flags,
      localHeaderOffset,
    });
  }

  // 3) Extract each file by reading local header + file data
  fs.mkdirSync(outFolder, { recursive: true });

  for (const file of files) {
    const { filename, method, compSize, unCompSize, localHeaderOffset } = file;

    // Some files are directories (filename ends with "/")
    if (filename.endsWith("/")) {
      const dirPath = path.join(outFolder, filename);
      fs.mkdirSync(dirPath, { recursive: true });
      continue;
    }

    // Move to local header
    let lhPtr = localHeaderOffset;
    const localSig = zipBuffer.readUInt32LE(lhPtr);
    if (localSig !== 0x04034b50) {
      throw new Error(
        `Local file header signature mismatch at ${lhPtr} for ${filename}`,
      );
    }
    lhPtr += 4;

    // local file header structure:
    //  0..1   version needed to extract
    //  2..3   general purpose bit flag
    //  4..5   compression method
    //  6..7   last mod time
    //  8..9   last mod date
    //  10..13 crc32
    //  14..17 compressed size
    //  18..21 uncompressed size
    //  22..23 filename length (fLen)
    //  24..25 extra field length (xLen)
    /* const lhVerNeed= */ zipBuffer.readUInt16LE(lhPtr);
    lhPtr += 2;
    /* const lhFlags  = */ zipBuffer.readUInt16LE(lhPtr);
    lhPtr += 2;
    /* const lhMethod = */ zipBuffer.readUInt16LE(lhPtr);
    lhPtr += 2;
    lhPtr += 2; // skip mod time
    lhPtr += 2; // skip mod date
    lhPtr += 4; // skip CRC
    lhPtr += 4; // skip comp size
    lhPtr += 4; // skip uncomp size
    const lhFNameLen = zipBuffer.readUInt16LE(lhPtr);
    lhPtr += 2;
    const lhXLen = zipBuffer.readUInt16LE(lhPtr);
    lhPtr += 2;

    // skip the filename + extra in the local header
    lhPtr += lhFNameLen;
    lhPtr += lhXLen;

    // Now, `lhPtr` points to the compressed data
    const fileData = zipBuffer.slice(lhPtr, lhPtr + compSize);

    // Build output path
    const outPath = path.join(outFolder, filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });

    // Decompress (method=8 => deflate, method=0 => stored)
    if (method === 0) {
      // No compression
      fs.writeFileSync(outPath, fileData);
    } else if (method === 8) {
      // Deflate
      const unzipped = zlib.inflateRawSync(fileData);
      fs.writeFileSync(outPath, unzipped);
    } else {
      throw new Error(
        `Unsupported compression method (${method}) for file ${filename}`,
      );
    }
  }
}
