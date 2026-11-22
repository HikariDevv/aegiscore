package com.dips.aegiscore;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class PcCleaner {
    public record CleanResult(
            boolean dryRun,
            List<Path> targets,
            int filesEligible,
            int filesRemoved,
            int filesLockedOrSkipped,
            long bytesReclaimable,
            long bytesFreed
    ) {
    }

    private PcCleaner() {
    }

    public static List<Path> safeTempTargets() {
        Set<Path> unique = new LinkedHashSet<>();
        addIfDir(unique, System.getenv("TEMP"));
        addIfDir(unique, System.getenv("TMP"));
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null) {
            addIfDir(unique, Path.of(localAppData, "Temp").toString());
            addIfDir(unique, Path.of(localAppData, "CrashDumps").toString());
        }
        String winDir = System.getenv("SystemRoot");
        if (winDir != null) {
            addIfDir(unique, Path.of(winDir, "Temp").toString());
        }
        return new ArrayList<>(unique);
    }

    public static CleanResult clean(List<Path> targets, boolean apply) {
        int[] eligible = {0};
        int[] removed = {0};
        int[] skipped = {0};
        long[] reclaimable = {0L};
        long[] freed = {0L};

        for (Path root : targets) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            try {
                Files.walkFileTree(root, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        long sz = attrs.size();
                        eligible[0]++;
                        reclaimable[0] += sz;
                        if (apply) {
                            try {
                                Files.delete(file);
                                removed[0]++;
                                freed[0] += sz;
                            } catch (IOException e) {
                                skipped[0]++;
                            }
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                        if (apply && !dir.equals(root)) {
                            try {
                                Files.delete(dir);
                            } catch (IOException ignored) {
                            }
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        skipped[0]++;
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException ignored) {
            }
        }

        return new CleanResult(!apply, targets, eligible[0], removed[0], skipped[0], reclaimable[0], freed[0]);
    }

    private static void addIfDir(Set<Path> set, String dir) {
        if (dir == null || dir.isBlank()) {
            return;
        }
        Path p = Path.of(dir).toAbsolutePath().normalize();
        if (Files.isDirectory(p)) {
            set.add(p);
        }
    }
}
