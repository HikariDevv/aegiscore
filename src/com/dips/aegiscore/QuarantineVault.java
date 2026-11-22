package com.dips.aegiscore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

public final class QuarantineVault {
    private static final byte[] MAGIC = new byte[]{'A', 'G', 'S', 'Q'};
    private static final SecureRandom RANDOM = new SecureRandom();

    public record QuarantineEntry(String id, String originalPath, String sha256, String timestamp, int score, long sizeBytes) {
    }

    private QuarantineVault() {
    }

    public static Path vaultDir() {
        return Path.of(System.getProperty("user.home"), ".aegiscore", "quarantine");
    }

    private static Path keyPath() {
        return Path.of(System.getProperty("user.home"), ".aegiscore", "vault.key");
    }

    public static QuarantineEntry isolate(Path target, int score, String reason) throws Exception {
        if (!Files.isRegularFile(target)) {
            throw new IllegalArgumentException("File not found: " + target);
        }
        Files.createDirectories(vaultDir());
        SecretKey key = loadOrCreateKey();

        byte[] raw = Files.readAllBytes(target);
        String sha = ThreatScanner.sha256Hex(raw);
        String id = UUID.randomUUID().toString().substring(0, 8);
        String ts = Instant.now().toString();
        String origPath = target.toAbsolutePath().toString();
        String meta = origPath + "\n" + sha + "\n" + ts + "\n" + score + "\n" + (reason == null ? "" : reason);
        byte[] metaBytes = meta.getBytes(StandardCharsets.UTF_8);

        ByteBuffer plain = ByteBuffer.allocate(4 + metaBytes.length + 4 + raw.length);
        plain.putInt(metaBytes.length);
        plain.put(metaBytes);
        plain.putInt(raw.length);
        plain.put(raw);

        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(plain.array());

        ByteBuffer out = ByteBuffer.allocate(4 + 12 + encrypted.length);
        out.put(MAGIC);
        out.put(iv);
        out.put(encrypted);

        Path vaultFile = vaultDir().resolve(id + ".aegisq");
        Files.write(vaultFile, out.array());
        Files.delete(target);

        return new QuarantineEntry(id, origPath, sha, ts, score, raw.length);
    }

    public static List<QuarantineEntry> list() throws Exception {
        List<QuarantineEntry> entries = new ArrayList<>();
        if (!Files.isDirectory(vaultDir())) {
            return entries;
        }
        SecretKey key = loadOrCreateKey();
        try (Stream<Path> stream = Files.list(vaultDir())) {
            for (Path p : stream.filter(f -> f.getFileName().toString().endsWith(".aegisq")).toList()) {
                try {
                    DecryptedRecord rec = readRecord(p, key);
                    String id = p.getFileName().toString().replace(".aegisq", "");
                    entries.add(new QuarantineEntry(id, rec.originalPath, rec.sha256, rec.timestamp, rec.score, rec.data.length));
                } catch (Exception ignored) {
                }
            }
        }
        return entries;
    }

    public static Path restore(String id, Path overrideDir) throws Exception {
        Path vaultFile = vaultDir().resolve(id + ".aegisq");
        if (!Files.isRegularFile(vaultFile)) {
            throw new IllegalArgumentException("Quarantine entry not found: " + id);
        }
        SecretKey key = loadOrCreateKey();
        DecryptedRecord rec = readRecord(vaultFile, key);
        Path dest = overrideDir != null
                ? overrideDir.resolve(Path.of(rec.originalPath).getFileName())
                : Path.of(rec.originalPath);
        Path parent = dest.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(dest, rec.data);
        Files.delete(vaultFile);
        return dest;
    }

    public static void deletePermanently(String id) throws IOException {
        Path vaultFile = vaultDir().resolve(id + ".aegisq");
        if (!Files.isRegularFile(vaultFile)) {
            throw new IllegalArgumentException("Quarantine entry not found: " + id);
        }
        long size = Files.size(vaultFile);
        if (size > 0 && size <= 64L * 1024L * 1024L) {
            byte[] zeros = new byte[(int) size];
            Files.write(vaultFile, zeros);
        }
        Files.delete(vaultFile);
    }

    private record DecryptedRecord(String originalPath, String sha256, String timestamp, int score, byte[] data) {
    }

    private static DecryptedRecord readRecord(Path vaultFile, SecretKey key) throws Exception {
        byte[] all = Files.readAllBytes(vaultFile);
        if (all.length < 32 || all[0] != MAGIC[0] || all[1] != MAGIC[1] || all[2] != MAGIC[2] || all[3] != MAGIC[3]) {
            throw new IOException("Invalid quarantine file format.");
        }
        byte[] iv = Arrays.copyOfRange(all, 4, 16);
        byte[] ct = Arrays.copyOfRange(all, 16, all.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.doFinal(ct);

        ByteBuffer buf = ByteBuffer.wrap(plain);
        int metaLen = buf.getInt();
        byte[] metaBytes = new byte[metaLen];
        buf.get(metaBytes);
        int dataLen = buf.getInt();
        byte[] data = new byte[dataLen];
        buf.get(data);

        String[] lines = new String(metaBytes, StandardCharsets.UTF_8).split("\n", -1);
        String orig = lines.length > 0 ? lines[0] : "restored.bin";
        String sha = lines.length > 1 ? lines[1] : "";
        String ts = lines.length > 2 ? lines[2] : "";
        int score = lines.length > 3 ? Integer.parseInt(lines[3]) : 0;
        return new DecryptedRecord(orig, sha, ts, score, data);
    }

    private static SecretKey loadOrCreateKey() throws IOException {
        Path kp = keyPath();
        if (Files.isRegularFile(kp)) {
            byte[] keyBytes = Files.readAllBytes(kp);
            if (keyBytes.length == 32) {
                return new SecretKeySpec(keyBytes, "AES");
            }
        }
        Files.createDirectories(kp.getParent());
        byte[] keyBytes = new byte[32];
        RANDOM.nextBytes(keyBytes);
        Files.write(kp, keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }
}
