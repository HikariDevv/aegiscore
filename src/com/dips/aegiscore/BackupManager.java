package com.dips.aegiscore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class BackupManager {
    private static final String MANIFEST_NAME = ".aegis-manifest.txt";

    public record BackupSummary(Path archivePath, int fileCount, long rawBytes, long archiveBytes) {
    }

    public record VerifySummary(int checkedFiles, int validFiles, int corruptedFiles, int missingFiles) {
        public boolean isOk() {
            return corruptedFiles == 0 && missingFiles == 0 && checkedFiles > 0;
        }
    }

    private BackupManager() {
    }

    public static BackupSummary createBackup(Path sourceDir, Path outputZip) throws IOException {
        if (!Files.exists(sourceDir)) {
            throw new IllegalArgumentException("Source path does not exist: " + sourceDir);
        }
        Path absSource = sourceDir.toAbsolutePath().normalize();
        Path absOut = outputZip.toAbsolutePath().normalize();
        Path parent = absOut.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Map<String, String> manifest = new LinkedHashMap<>();
        long[] rawBytes = {0L};
        int[] count = {0};

        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(absOut))) {
            zos.setLevel(Deflater.BEST_COMPRESSION);
            if (Files.isRegularFile(absSource)) {
                String entryName = absSource.getFileName().toString();
                String hash = writeZipEntry(zos, absSource, entryName, rawBytes);
                manifest.put(entryName, hash);
                count[0]++;
            } else {
                Files.walkFileTree(absSource, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        if (file.toAbsolutePath().normalize().equals(absOut)) {
                            return FileVisitResult.CONTINUE;
                        }
                        String rel = absSource.relativize(file).toString().replace('\\', '/');
                        String hash = writeZipEntry(zos, file, rel, rawBytes);
                        manifest.put(rel, hash);
                        count[0]++;
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        return FileVisitResult.CONTINUE;
                    }
                });
            }

            StringBuilder mf = new StringBuilder();
            for (Map.Entry<String, String> e : manifest.entrySet()) {
                mf.append(e.getValue()).append("  ").append(e.getKey()).append('\n');
            }
            zos.putNextEntry(new ZipEntry(MANIFEST_NAME));
            zos.write(mf.toString().getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        long zipBytes = Files.size(absOut);
        return new BackupSummary(absOut, count[0], rawBytes[0], zipBytes);
    }

    public static VerifySummary verifyBackup(Path zipPath) throws IOException {
        if (!Files.isRegularFile(zipPath)) {
            throw new IllegalArgumentException("Backup archive not found: " + zipPath);
        }
        try (ZipFile zf = new ZipFile(zipPath.toFile())) {
            ZipEntry mfEntry = zf.getEntry(MANIFEST_NAME);
            if (mfEntry == null) {
                throw new IOException("Backup archive is missing " + MANIFEST_NAME);
            }
            String mfText;
            try (InputStream in = zf.getInputStream(mfEntry)) {
                mfText = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }

            int checked = 0;
            int valid = 0;
            int corrupted = 0;
            int missing = 0;

            for (String line : mfText.split("\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int sep = trimmed.indexOf("  ");
                if (sep <= 0) {
                    continue;
                }
                String expectedHash = trimmed.substring(0, sep);
                String entryName = trimmed.substring(sep + 2);
                checked++;

                ZipEntry entry = zf.getEntry(entryName);
                if (entry == null) {
                    missing++;
                    continue;
                }
                try (InputStream in = zf.getInputStream(entry)) {
                    String actualHash = streamSha256(in);
                    if (expectedHash.equalsIgnoreCase(actualHash)) {
                        valid++;
                    } else {
                        corrupted++;
                    }
                }
            }
            return new VerifySummary(checked, valid, corrupted, missing);
        }
    }

    public static int restoreBackup(Path zipPath, Path destDir) throws IOException {
        if (!Files.isRegularFile(zipPath)) {
            throw new IllegalArgumentException("Backup archive not found: " + zipPath);
        }
        Path absDest = destDir.toAbsolutePath().normalize();
        Files.createDirectories(absDest);

        int restored = 0;
        try (ZipFile zf = new ZipFile(zipPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (MANIFEST_NAME.equals(name) || entry.isDirectory()) {
                    continue;
                }
                Path outPath = absDest.resolve(name).normalize();
                if (!outPath.startsWith(absDest)) {
                    throw new SecurityException("Blocked unsafe path in backup archive: " + name);
                }
                Files.createDirectories(outPath.getParent());
                try (InputStream in = zf.getInputStream(entry)) {
                    Files.copy(in, outPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
                restored++;
            }
        }
        return restored;
    }

    private static String writeZipEntry(ZipOutputStream zos, Path file, String entryName, long[] rawBytes) throws IOException {
        zos.putNextEntry(new ZipEntry(entryName));
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[16384];
            try (InputStream in = Files.newInputStream(file)) {
                int read;
                while ((read = in.read(buf)) != -1) {
                    zos.write(buf, 0, read);
                    md.update(buf, 0, read);
                    rawBytes[0] += read;
                }
            }
            zos.closeEntry();
            return hex(md.digest());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("SHA-256 computation failed", e);
        }
    }

    private static String streamSha256(InputStream in) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[16384];
            int read;
            while ((read = in.read(buf)) != -1) {
                md.update(buf, 0, read);
            }
            return hex(md.digest());
        } catch (Exception e) {
            throw new IOException("SHA-256 computation failed", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
