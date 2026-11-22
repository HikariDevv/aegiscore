package com.dips.aegiscore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class ThreatScanner {
    private static final String EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private static final long MAX_INSPECT_BYTES = 24L * 1024L * 1024L;

    private static final Set<String> SKIP_DIRS = Set.of(
            "$recycle.bin", "system volume information", "windows.old", "winsxs",
            "node_modules", ".git", "installer"
    );

    private static final Set<String> INTERESTING_EXTS = Set.of(
            ".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".msi", ".jar",
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".hta", ".wsf", ".py", ".sh", ".reg",
            ".jpg", ".jpeg", ".png", ".pdf", ".txt", ".docx", ".xlsx"
    );

    public record ThreatFinding(Path path, int score, String sha256, long sizeBytes, List<String> reasons) {
    }

    public record ScanSummary(
            int totalFiles,
            long totalBytes,
            int skippedFiles,
            List<ThreatFinding> findings,
            double elapsedSeconds
    ) {
    }

    private ThreatScanner() {
    }

    public static List<Path> quickScanRoots() {
        List<Path> roots = new ArrayList<>();
        String userHome = System.getProperty("user.home");
        if (userHome != null) {
            addIfDir(roots, Path.of(userHome, "Desktop"));
            addIfDir(roots, Path.of(userHome, "Downloads"));
            addIfDir(roots, Path.of(userHome, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }
        String temp = System.getenv("TEMP");
        if (temp != null) {
            addIfDir(roots, Path.of(temp));
        }
        String programData = System.getenv("ProgramData");
        if (programData != null) {
            addIfDir(roots, Path.of(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }
        return roots;
    }

    public static ScanSummary scanPaths(List<Path> roots, boolean deepMode, boolean showProgress) throws Exception {
        long startNanos = System.nanoTime();
        Set<String> knownBadHashes = loadCustomSignatures();
        List<Path> candidates = collectFiles(roots, deepMode);

        int threads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger processed = new AtomicInteger(0);
        AtomicInteger skipped = new AtomicInteger(0);
        AtomicLong totalBytes = new AtomicLong(0);
        List<ThreatFinding> findings = new CopyOnWriteArrayList<>();

        int total = candidates.size();
        List<Future<?>> futures = new ArrayList<>(total);

        for (Path file : candidates) {
            futures.add(pool.submit(() -> {
                try {
                    long size = Files.size(file);
                    totalBytes.addAndGet(size);
                    ThreatFinding finding = inspectFile(file, size, knownBadHashes, deepMode);
                    if (finding != null) {
                        findings.add(finding);
                    }
                } catch (Exception e) {
                    skipped.incrementAndGet();
                } finally {
                    int done = processed.incrementAndGet();
                    if (showProgress && (done == total || done % 25 == 0)) {
                        printProgress(done, total, findings.size());
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();
        if (showProgress && total > 0) {
            System.out.println();
        }

        List<ThreatFinding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator.comparingInt(ThreatFinding::score).reversed());
        double elapsedSec = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        return new ScanSummary(total, totalBytes.get(), skipped.get(), sorted, elapsedSec);
    }

    public static ThreatFinding inspectSingleFile(Path file) throws IOException {
        long size = Files.size(file);
        Set<String> sigs = loadCustomSignatures();
        ThreatFinding found = inspectFile(file, size, sigs, true);
        if (found != null) {
            return found;
        }
        byte[] data = readBounded(file, size);
        return new ThreatFinding(file, 0, sha256Hex(data), size, List.of());
    }

    private static ThreatFinding inspectFile(Path file, long size, Set<String> knownBadHashes, boolean deepMode) throws IOException {
        if (size <= 0 || size > MAX_INSPECT_BYTES) {
            return null;
        }
        String fileName = file.getFileName() == null ? "" : file.getFileName().toString();
        String lowerName = fileName.toLowerCase(Locale.ROOT);

        if (!deepMode && !isInterestingFile(lowerName)) {
            return null;
        }

        byte[] data = readBounded(file, size);
        int score = 0;
        List<String> reasons = new ArrayList<>();

        String sha256 = null;
        if (data.length <= 1024) {
            String probe = new String(data, StandardCharsets.US_ASCII);
            if (probe.contains(EICAR_SIGNATURE)) {
                score = 100;
                reasons.add("EICAR Standard Antivirus Test Signature detected");
            }
        }

        if (score < 100 && !knownBadHashes.isEmpty()) {
            sha256 = sha256Hex(data);
            if (knownBadHashes.contains(sha256)) {
                score = 100;
                reasons.add("Matched local malicious SHA-256 signature database");
            }
        }

        if (score < 100) {
            if (PeScanner.isPeMagic(data)) {
                PeScanner.PeResult pe = PeScanner.analyze(data, lowerName);
                score += pe.score();
                reasons.addAll(pe.findings());
            }

            ScriptScanner.ScriptResult sc = ScriptScanner.analyze(data, lowerName);
            score += sc.score();
            reasons.addAll(sc.findings());

            String fullLower = file.toAbsolutePath().toString().toLowerCase(Locale.ROOT);
            if ((lowerName.endsWith(".exe") || lowerName.endsWith(".scr") || lowerName.endsWith(".vbs") || lowerName.endsWith(".ps1"))
                    && (fullLower.contains("\\appdata\\local\\temp\\") || fullLower.contains("\\windows\\temp\\"))
                    && score > 0) {
                score += 15;
                reasons.add("Suspicious executable/script located inside Temp directory");
            }
        }

        score = Math.min(100, score);
        if (score < 30) {
            return null;
        }
        if (sha256 == null) {
            sha256 = sha256Hex(data);
        }
        return new ThreatFinding(file.toAbsolutePath(), score, sha256, size, reasons);
    }

    private static List<Path> collectFiles(List<Path> roots, boolean deepMode) {
        List<Path> collected = new ArrayList<>();
        for (Path root : roots) {
            if (!Files.exists(root)) {
                continue;
            }
            if (Files.isRegularFile(root)) {
                collected.add(root);
                continue;
            }
            try {
                Files.walkFileTree(root, Collections.emptySet(), Integer.MAX_VALUE, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        Path name = dir.getFileName();
                        if (name != null) {
                            String lower = name.toString().toLowerCase(Locale.ROOT);
                            if (SKIP_DIRS.contains(lower)) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (!attrs.isRegularFile() || attrs.size() <= 0 || attrs.size() > MAX_INSPECT_BYTES) {
                            return FileVisitResult.CONTINUE;
                        }
                        String name = file.getFileName() == null ? "" : file.getFileName().toString().toLowerCase(Locale.ROOT);
                        if (deepMode || isInterestingFile(name)) {
                            collected.add(file);
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException ignored) {
            }
        }
        return collected;
    }

    private static boolean isInterestingFile(String lowerName) {
        if (ScriptScanner.hasDoubleExtension(lowerName)) {
            return true;
        }
        for (String ext : INTERESTING_EXTS) {
            if (lowerName.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] readBounded(Path file, long size) throws IOException {
        if (size <= MAX_INSPECT_BYTES) {
            return Files.readAllBytes(file);
        }
        return new byte[0];
    }

    private static Set<String> loadCustomSignatures() {
        Set<String> hashes = new HashSet<>();
        hashes.add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        String home = System.getProperty("user.home");
        if (home != null) {
            Path sigFile = Path.of(home, ".aegiscore", "signatures.txt");
            if (Files.isRegularFile(sigFile)) {
                try {
                    for (String line : Files.readAllLines(sigFile, StandardCharsets.UTF_8)) {
                        String trimmed = line.trim().toLowerCase(Locale.ROOT);
                        if (trimmed.length() == 64 && !trimmed.startsWith("#")) {
                            hashes.add(trimmed);
                        }
                    }
                } catch (IOException ignored) {
                }
            }
        }
        return hashes;
    }

    private static void addIfDir(List<Path> list, Path p) {
        if (Files.isDirectory(p) && !list.contains(p)) {
            list.add(p);
        }
    }

    private static void printProgress(int done, int total, int threats) {
        int pct = total == 0 ? 100 : (done * 100) / total;
        int filled = pct / 4;
        StringBuilder bar = new StringBuilder(25);
        for (int i = 0; i < 25; i++) {
            bar.append(i < filled ? '#' : '-');
        }
        System.out.printf(Locale.ROOT, "\r  [%s] %3d%%  (%d/%d files | %d threats)", bar, pct, done, total, threats);
        System.out.flush();
    }

    public static void writeJsonReport(Path outPath, ScanSummary summary) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"timestamp\": \"").append(Instant.now()).append("\",\n");
        sb.append("  \"totalFiles\": ").append(summary.totalFiles()).append(",\n");
        sb.append("  \"totalBytes\": ").append(summary.totalBytes()).append(",\n");
        sb.append("  \"skippedFiles\": ").append(summary.skippedFiles()).append(",\n");
        sb.append("  \"elapsedSeconds\": ").append(String.format(Locale.ROOT, "%.3f", summary.elapsedSeconds())).append(",\n");
        sb.append("  \"threats\": [\n");
        List<ThreatFinding> list = summary.findings();
        for (int i = 0; i < list.size(); i++) {
            ThreatFinding f = list.get(i);
            sb.append("    {\n");
            sb.append("      \"path\": \"").append(escapeJson(f.path().toString())).append("\",\n");
            sb.append("      \"score\": ").append(f.score()).append(",\n");
            sb.append("      \"severity\": \"").append(ConsoleUi.severityLabel(f.score())).append("\",\n");
            sb.append("      \"sha256\": \"").append(f.sha256()).append("\",\n");
            sb.append("      \"sizeBytes\": ").append(f.sizeBytes()).append(",\n");
            sb.append("      \"reasons\": [");
            for (int r = 0; r < f.reasons().size(); r++) {
                if (r > 0) {
                    sb.append(", ");
                }
                sb.append("\"").append(escapeJson(f.reasons().get(r))).append("\"");
            }
            sb.append("]\n");
            sb.append("    }").append(i + 1 < list.size() ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        Path parent = outPath.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(outPath, sb.toString(), StandardCharsets.UTF_8);
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
