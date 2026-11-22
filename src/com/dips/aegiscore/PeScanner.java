package com.dips.aegiscore;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class PeScanner {
    private static final Set<String> PACKER_SECTIONS = Set.of(
            "upx0", "upx1", "upx2", ".upx", "themida", ".vmp0", ".vmp1", ".vmp2",
            ".aspack", ".adata", ".mpress1", ".mpress2", ".enigma1", ".enigma2",
            ".petite", ".nsp0", ".nsp1", ".obsidiu"
    );

    private static final Set<String> INJECTION_APIS = Set.of(
            "virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
            "ntunmapviewofsection", "zwunmapviewofsection", "queueuserapc", "ntqueueapcthread",
            "setthreadcontext", "resumethread", "ntallocatevirtualmemory", "ntwritevirtualmemory"
    );

    private static final Set<String> SPY_APIS = Set.of(
            "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
            "getforegroundwindow", "cryptunprotectdata", "minidumpwritedump",
            "lsaenumeratelogonsessions", "bitblt", "getclipboarddata"
    );

    private static final Set<String> NETWORK_APIS = Set.of(
            "urldownloadtofilea", "urldownloadtofilew", "internetopena", "internetopenw",
            "internetopenurla", "internetopenurlw", "winhttpopen", "winhttpsendrequest",
            "wsastartup", "wsasocketa", "wsasocketw", "connect"
    );

    private static final Set<String> EVASION_APIS = Set.of(
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "amsiscanbuffer", "etweventwrite", "virtualprotect", "virtualprotectex"
    );

    private static final Set<String> PERSISTENCE_APIS = Set.of(
            "regsetvalueexa", "regsetvalueexw", "createservicea", "createservicew",
            "startservicea", "startservicew"
    );

    private static final Set<String> CRYPTO_APIS = Set.of(
            "cryptencrypt", "bcryptencrypt", "cryptgenkey", "cryptimportkey"
    );

    private record Section(String name, long virtualSize, long virtualAddress, long rawSize, long rawOffset, long characteristics, double entropy) {
    }

    public record PeResult(int score, List<String> findings) {
    }

    private PeScanner() {
    }

    public static boolean isPeMagic(byte[] data) {
        return data != null && data.length >= 64 && data[0] == 'M' && data[1] == 'Z';
    }

    public static PeResult analyze(byte[] data, String lowerName) {
        List<String> findings = new ArrayList<>();
        int score = 0;

        if (!isPeMagic(data)) {
            return new PeResult(0, findings);
        }

        if (isDisguisedExtension(lowerName)) {
            score += 45;
            findings.add("Disguised PE executable with non-executable extension");
        }

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int peOffset = buf.getInt(0x3C);
        if (peOffset < 0 || peOffset + 24 > data.length) {
            return new PeResult(score, findings);
        }
        if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0) {
            return new PeResult(score, findings);
        }

        int sectionCount = Short.toUnsignedInt(buf.getShort(peOffset + 6));
        int optHeaderSize = Short.toUnsignedInt(buf.getShort(peOffset + 20));
        int optOffset = peOffset + 24;
        if (optOffset + 2 > data.length) {
            return new PeResult(score, findings);
        }

        int magic = Short.toUnsignedInt(buf.getShort(optOffset));
        boolean isPe64 = magic == 0x20B;
        if (magic != 0x10B && !isPe64) {
            return new PeResult(score, findings);
        }

        int sectionTableOffset = optOffset + optHeaderSize;
        List<Section> sections = new ArrayList<>();
        int highEntropySections = 0;
        int rwxSections = 0;

        for (int i = 0; i < sectionCount && i < 64; i++) {
            int off = sectionTableOffset + i * 40;
            if (off + 40 > data.length) {
                break;
            }
            String secName = readFixedAscii(data, off, 8);
            long vSize = Integer.toUnsignedLong(buf.getInt(off + 8));
            long vAddr = Integer.toUnsignedLong(buf.getInt(off + 12));
            long rawSize = Integer.toUnsignedLong(buf.getInt(off + 16));
            long rawOff = Integer.toUnsignedLong(buf.getInt(off + 20));
            long chars = Integer.toUnsignedLong(buf.getInt(off + 36));
            double entropy = calcSectionEntropy(data, rawOff, rawSize);
            sections.add(new Section(secName, vSize, vAddr, rawSize, rawOff, chars, entropy));

            String lowerSec = secName.toLowerCase(Locale.ROOT);
            if (PACKER_SECTIONS.contains(lowerSec)) {
                score += 25;
                findings.add("Known packer/crypter section: " + secName);
            }
            if ((chars & 0xE0000000L) == 0xE0000000L) {
                rwxSections++;
            }
            if (entropy >= 7.25 && rawSize >= 4096) {
                highEntropySections++;
            }
        }

        if (rwxSections > 0) {
            score += 25;
            findings.add("Executable + Writable (RWX) memory section detected (" + rwxSections + ")");
        }
        if (highEntropySections > 0) {
            score += 18;
            findings.add("High-entropy packed/encrypted PE section (" + highEntropySections + " section(s) >= 7.25)");
        }

        Set<String> imports = parseImports(data, buf, optOffset, isPe64, sections);
        int injHits = countMatches(imports, INJECTION_APIS);
        int spyHits = countMatches(imports, SPY_APIS);
        int netHits = countMatches(imports, NETWORK_APIS);
        int evaHits = countMatches(imports, EVASION_APIS);
        int perHits = countMatches(imports, PERSISTENCE_APIS);
        int cryHits = countMatches(imports, CRYPTO_APIS);

        if (injHits >= 2) {
            score += 35;
            findings.add("Process injection/hollowing API cluster (" + injHits + " APIs)");
        }
        if (spyHits >= 2) {
            score += 30;
            findings.add("Keylogger/credential spy API cluster (" + spyHits + " APIs)");
        }
        if (injHits >= 1 && netHits >= 1) {
            score += 20;
            findings.add("Network + process manipulation combination");
        }
        if (evaHits >= 2) {
            score += 15;
            findings.add("Anti-debug / AMSI / ETW evasion APIs (" + evaHits + ")");
        }
        if (perHits >= 1 && netHits >= 1) {
            score += 15;
            findings.add("Persistence + network API combination");
        }
        if (cryHits >= 1 && highEntropySections > 0) {
            score += 12;
            findings.add("Crypto APIs combined with high-entropy sections");
        }

        String ascii = extractAsciiLower(data, 512 * 1024);
        if (ascii.contains("discord.com/api/webhooks/") || ascii.contains("discordapp.com/api/webhooks/")) {
            score += 35;
            findings.add("Embedded Discord webhook URL (common stealer exfiltration)");
        }
        if (ascii.contains("api.telegram.org/bot")) {
            score += 30;
            findings.add("Embedded Telegram Bot API endpoint");
        }
        if (ascii.contains("vssadmin") && ascii.contains("delete shadows")) {
            score += 45;
            findings.add("Ransomware shadow-copy deletion command string");
        }
        if (ascii.contains("add-mppreference") || ascii.contains("disablerealtimemonitoring")) {
            score += 35;
            findings.add("Windows Defender tampering command string");
        }
        if (ascii.contains("login data") && ascii.contains("local state")) {
            score += 30;
            findings.add("Browser credential database target paths");
        }

        return new PeResult(Math.min(100, score), findings);
    }

    private static Set<String> parseImports(byte[] data, ByteBuffer buf, int optOffset, boolean isPe64, List<Section> sections) {
        Set<String> imports = new HashSet<>();
        int dataDirOffset = optOffset + (isPe64 ? 112 : 96);
        int importDirEntry = dataDirOffset + 8;
        if (importDirEntry + 8 > data.length) {
            return imports;
        }
        long importRva = Integer.toUnsignedLong(buf.getInt(importDirEntry));
        long importSize = Integer.toUnsignedLong(buf.getInt(importDirEntry + 4));
        if (importRva == 0 || importSize == 0) {
            return imports;
        }
        int dirOffset = rvaToOffset(importRva, sections);
        if (dirOffset < 0) {
            return imports;
        }

        for (int desc = 0; desc < 128; desc++) {
            int entry = dirOffset + desc * 20;
            if (entry + 20 > data.length) {
                break;
            }
            long origFirstThunk = Integer.toUnsignedLong(buf.getInt(entry));
            long nameRva = Integer.toUnsignedLong(buf.getInt(entry + 12));
            long firstThunk = Integer.toUnsignedLong(buf.getInt(entry + 16));
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) {
                break;
            }
            long thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            int thunkOff = rvaToOffset(thunkRva, sections);
            if (thunkOff < 0) {
                continue;
            }

            int step = isPe64 ? 8 : 4;
            for (int t = 0; t < 512; t++) {
                int pos = thunkOff + t * step;
                if (pos + step > data.length) {
                    break;
                }
                long val = isPe64 ? buf.getLong(pos) : Integer.toUnsignedLong(buf.getInt(pos));
                if (val == 0) {
                    break;
                }
                boolean isOrdinal = isPe64 ? (val < 0) : ((val & 0x80000000L) != 0);
                if (isOrdinal) {
                    continue;
                }
                int hintNameOff = rvaToOffset(val & 0x7FFFFFFFL, sections);
                if (hintNameOff >= 0 && hintNameOff + 2 < data.length) {
                    String fn = readNullAscii(data, hintNameOff + 2, 128);
                    if (!fn.isEmpty()) {
                        imports.add(fn.toLowerCase(Locale.ROOT));
                    }
                }
            }
        }
        return imports;
    }

    private static int rvaToOffset(long rva, List<Section> sections) {
        for (Section s : sections) {
            long span = Math.max(s.virtualSize(), s.rawSize());
            if (rva >= s.virtualAddress() && rva < s.virtualAddress() + span) {
                long delta = rva - s.virtualAddress();
                long fileOff = s.rawOffset() + delta;
                if (fileOff >= 0 && fileOff < Integer.MAX_VALUE) {
                    return (int) fileOff;
                }
            }
        }
        return -1;
    }

    private static double calcSectionEntropy(byte[] data, long offset, long size) {
        if (size <= 0 || offset < 0 || offset >= data.length) {
            return 0.0;
        }
        int start = (int) offset;
        int len = (int) Math.min(size, data.length - offset);
        if (len <= 0) {
            return 0.0;
        }
        int[] freq = new int[256];
        for (int i = start; i < start + len; i++) {
            freq[data[i] & 0xFF]++;
        }
        double entropy = 0.0;
        double dLen = len;
        for (int f : freq) {
            if (f > 0) {
                double p = f / dLen;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }

    private static int countMatches(Set<String> imports, Set<String> targets) {
        int count = 0;
        for (String t : targets) {
            if (imports.contains(t)) {
                count++;
            }
        }
        return count;
    }

    private static boolean isDisguisedExtension(String lowerName) {
        return lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg") || lowerName.endsWith(".png")
                || lowerName.endsWith(".pdf") || lowerName.endsWith(".txt") || lowerName.endsWith(".docx")
                || lowerName.endsWith(".xlsx") || lowerName.endsWith(".mp3") || lowerName.endsWith(".mp4");
    }

    private static String readFixedAscii(byte[] data, int off, int maxLen) {
        int end = off;
        int limit = Math.min(data.length, off + maxLen);
        while (end < limit && data[end] != 0) {
            end++;
        }
        return new String(data, off, end - off, StandardCharsets.US_ASCII).trim();
    }

    private static String readNullAscii(byte[] data, int off, int maxLen) {
        int end = off;
        int limit = Math.min(data.length, off + maxLen);
        while (end < limit && data[end] >= 32 && data[end] <= 126) {
            end++;
        }
        return new String(data, off, end - off, StandardCharsets.US_ASCII);
    }

    private static String extractAsciiLower(byte[] data, int limit) {
        int len = Math.min(data.length, limit);
        StringBuilder sb = new StringBuilder(len / 2);
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xFF;
            if (b >= 32 && b <= 126) {
                sb.append((char) Character.toLowerCase(b));
            } else {
                sb.append(' ');
            }
        }
        return sb.toString();
    }
}
