#include "dlu/core/signatures.hpp"

namespace dlu::core {

const std::vector<Signature>& builtin_signatures() {
    static const std::vector<Signature> db = {
        // --- Archives ---
        {"zip", "ZIP archive", "archive", {0x50,0x4B,0x03,0x04}, 0, "application/zip", {"zip","jar","apk","docx","xlsx","pptx","odt"}},
        {"zip_empty", "ZIP (empty)", "archive", {0x50,0x4B,0x05,0x06}, 0, "application/zip", {"zip"}},
        {"rar4", "RAR archive v1.5-4.x", "archive", {0x52,0x61,0x72,0x21,0x1A,0x07,0x00}, 0, "application/x-rar", {"rar"}},
        {"rar5", "RAR archive v5+", "archive", {0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00}, 0, "application/x-rar", {"rar"}},
        {"7z", "7-Zip archive", "archive", {0x37,0x7A,0xBC,0xAF,0x27,0x1C}, 0, "application/x-7z-compressed", {"7z"}},
        {"gzip", "GZIP stream", "archive", {0x1F,0x8B}, 0, "application/gzip", {"gz","tgz"}},
        {"bzip2", "BZIP2 stream", "archive", {0x42,0x5A,0x68}, 0, "application/x-bzip2", {"bz2"}},
        {"xz", "XZ stream", "archive", {0xFD,0x37,0x7A,0x58,0x5A,0x00}, 0, "application/x-xz", {"xz"}},
        {"zstd", "Zstandard stream", "archive", {0x28,0xB5,0x2F,0xFD}, 0, "application/zstd", {"zst"}},
        // --- Documents ---
        {"pdf", "PDF document", "document", {0x25,0x50,0x44,0x46,0x2D}, 0, "application/pdf", {"pdf"}},
        {"ole", "OLE2 (legacy Office)", "document", {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}, 0, "application/x-ole-storage", {"doc","xls","ppt","msi"}},
        {"rtf", "RTF document", "document", {0x7B,0x5C,0x72,0x74,0x66}, 0, "application/rtf", {"rtf"}},
        // --- Binary / executables ---
        {"elf", "ELF binary", "binary", {0x7F,0x45,0x4C,0x46}, 0, "application/x-elf", {"elf","so","bin","o"}},
        {"pe", "DOS/PE executable", "binary", {0x4D,0x5A}, 0, "application/x-dosexec", {"exe","dll"}},
        {"macho64", "Mach-O 64-bit", "binary", {0xCF,0xFA,0xED,0xFE}, 0, "application/x-mach-binary", {"dylib","bin"}},
        {"wasm", "WebAssembly", "binary", {0x00,0x61,0x73,0x6D}, 0, "application/wasm", {"wasm"}},
        // --- Disk images / db ---
        {"sqlite", "SQLite database", "database", {0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00}, 0, "application/x-sqlite3", {"db","sqlite","sqlite3"}},
        {"iso", "ISO 9660 image", "image", {0x43,0x44,0x30,0x30,0x31}, 32769, "application/x-iso9660-image", {"iso"}},
        // --- Images ---
        {"png", "PNG image", "image", {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}, 0, "image/png", {"png"}},
        {"jpg", "JPEG image", "image", {0xFF,0xD8,0xFF}, 0, "image/jpeg", {"jpg","jpeg"}},
        {"gif87", "GIF image (87a)", "image", {0x47,0x49,0x46,0x38,0x37,0x61}, 0, "image/gif", {"gif"}},
        {"gif89", "GIF image (89a)", "image", {0x47,0x49,0x46,0x38,0x39,0x61}, 0, "image/gif", {"gif"}},
        {"webp", "WEBP image", "image", {0x52,0x49,0x46,0x46}, 0, "image/webp", {"webp"}},
        {"tiff_le", "TIFF image (LE)", "image", {0x49,0x49,0x2A,0x00}, 0, "image/tiff", {"tif","tiff"}},
        {"tiff_be", "TIFF image (BE)", "image", {0x4D,0x4D,0x00,0x2A}, 0, "image/tiff", {"tif","tiff"}},
        {"bmp", "BMP image", "image", {0x42,0x4D}, 0, "image/bmp", {"bmp"}},
        // --- Audio / video ---
        {"id3", "MP3 (ID3)", "media", {0x49,0x44,0x33}, 0, "audio/mpeg", {"mp3"}},
        {"flac", "FLAC audio", "media", {0x66,0x4C,0x61,0x43}, 0, "audio/flac", {"flac"}},
        {"wav", "WAV audio", "media", {0x52,0x49,0x46,0x46}, 0, "audio/wav", {"wav"}},
        {"mkv", "Matroska video", "media", {0x1A,0x45,0xDF,0xA3}, 0, "video/x-matroska", {"mkv","webm"}},
        {"mp4", "MP4 (ftyp)", "media", {0x66,0x74,0x79,0x70}, 4, "video/mp4", {"mp4","m4a","mov"}},
        // --- Crypto containers ---
        {"pgp", "PGP message (armored)", "crypto", {0x2D,0x2D,0x2D,0x2D,0x2D,0x42,0x45,0x47,0x49,0x4E,0x20,0x50,0x47,0x50}, 0, "application/pgp", {"asc","pgp","gpg"}},
        {"openssl_salt", "OpenSSL salted blob", "crypto", {0x53,0x61,0x6C,0x74,0x65,0x64,0x5F,0x5F}, 0, "application/octet-stream", {"enc"}},
        {"pem", "PEM block", "crypto", {0x2D,0x2D,0x2D,0x2D,0x2D,0x42,0x45,0x47,0x49,0x4E}, 0, "application/x-pem-file", {"pem","crt","key","ca"}},
        {"luks", "LUKS encrypted volume", "crypto", {0x4C,0x55,0x4B,0x53,0xBA,0xBE}, 0, "application/octet-stream", {"luks","img"}},
    };
    return db;
}

} // namespace dlu::core
