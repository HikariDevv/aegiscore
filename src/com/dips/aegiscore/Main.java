package com.dips.aegiscore;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

public final class Main {
    private static final String VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            runInteractiveMenu();
            return;
        }

        String command = args[0].toLowerCase(Locale.ROOT);
        try {
            switch (command) {
                case "scan" -> runScan(Arrays.copyOfRange(args, 1, args.length));
                case "audit" -> runAudit(Arrays.copyOfRange(args, 1, args.length));
                case "quarantine" -> runQuarantine(Arrays.copyOfRange(args, 1, args.length));
                case "clean" -> runClean(Arrays.copyOfRange(args, 1, args.length));
                case "backup" -> runBackup(Arrays.copyOfRange(args, 1, args.length));
                case "verify" -> runVerify(Arrays.copyOfRange(args, 1, args.length));
                case "restore" -> runRestore(Arrays.copyOfRange(args, 1, args.length));
                case "version", "-v", "--version" -> System.out.println("aegiscore " + VERSION);
                case "help", "-h", "--help" -> printUsage();
                default -> {
                    System.err.println(ConsoleUi.red("Unknown command: " + command));
                    printUsage();
                    System.exit(1);
                }
            }
        } catch (Exception e) {
            System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            System.exit(1);
        }
    }

    private static void runInteractiveMenu() {
        ConsoleUi.printBanner(VERSION);
        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.println();
            System.out.println(ConsoleUi.bold("Select an operation:"));
            System.out.println("  [1] Quick Malware Scan (Desktop, Downloads, Temp, Startup)");
            System.out.println("  [2] Deep Folder / Drive Scan");
            System.out.println("  [3] Windows System & Persistence Audit");
            System.out.println("  [4] Quarantine Vault (List / Restore / Delete)");
            System.out.println("  [5] Safe PC Temp Cleaner");
            System.out.println("  [6] Create Verified ZIP Backup");
            System.out.println("  [7] Verify or Restore Backup");
            System.out.println("  [0] Exit");
            System.out.print(ConsoleUi.cyan("\naegiscore> "));

            if (!sc.hasNextLine()) {
                break;
            }
            String choice = sc.nextLine().trim();
            try {
                switch (choice) {
                    case "1" -> executeScan(ThreatScanner.quickScanRoots(), false, null, false);
                    case "2" -> {
                        System.out.print("Folder or drive path (e.g. C:\\Users\\...): ");
                        String p = sc.nextLine().trim();
                        if (!p.isEmpty()) {
                            executeScan(List.of(Path.of(p)), true, null, false);
                        }
                    }
                    case "3" -> runAudit(new String[0]);
                    case "4" -> interactiveQuarantine(sc);
                    case "5" -> {
                        PcCleaner.CleanResult preview = PcCleaner.clean(PcCleaner.safeTempTargets(), false);
                        printCleanResult(preview);
                        if (preview.filesEligible() > 0) {
                            System.out.print("Delete removable temp files now? (y/N): ");
                            if ("y".equalsIgnoreCase(sc.nextLine().trim())) {
                                printCleanResult(PcCleaner.clean(PcCleaner.safeTempTargets(), true));
                            }
                        }
                    }
                    case "6" -> {
                        System.out.print("Source folder to back up: ");
                        String src = sc.nextLine().trim();
                        if (!src.isEmpty()) {
                            String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
                            Path out = Path.of("backup-" + stamp + ".zip");
                            BackupManager.BackupSummary bs = BackupManager.createBackup(Path.of(src), out);
                            printBackupSummary(bs);
                        }
                    }
                    case "7" -> {
                        System.out.print("Backup .zip path: ");
                        String zp = sc.nextLine().trim();
                        if (!zp.isEmpty()) {
                            BackupManager.VerifySummary vs = BackupManager.verifyBackup(Path.of(zp));
                            printVerifySummary(vs);
                            System.out.print("Restore to folder (leave blank to skip): ");
                            String dest = sc.nextLine().trim();
                            if (!dest.isEmpty()) {
                                int n = BackupManager.restoreBackup(Path.of(zp), Path.of(dest));
                                System.out.println(ConsoleUi.green("Restored " + n + " file(s) to " + Path.of(dest).toAbsolutePath()));
                            }
                        }
                    }
                    case "0", "exit", "quit" -> {
                        return;
                    }
                    default -> System.out.println(ConsoleUi.yellow("Invalid option."));
                }
            } catch (Exception e) {
                System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            }
        }
    }

    private static void interactiveQuarantine(Scanner sc) throws Exception {
        printQuarantineList(QuarantineVault.list());
        System.out.print("Action (restore <id> / delete <id> / enter to go back): ");
        String line = sc.nextLine().trim();
        if (line.isEmpty()) {
            return;
        }
        String[] parts = line.split("\\s+");
        if (parts.length == 2 && "restore".equalsIgnoreCase(parts[0])) {
            Path p = QuarantineVault.restore(parts[1], null);
            System.out.println(ConsoleUi.green("Restored to: " + p));
        } else if (parts.length == 2 && "delete".equalsIgnoreCase(parts[0])) {
            QuarantineVault.deletePermanently(parts[1]);
            System.out.println(ConsoleUi.green("Deleted permanently: " + parts[1]));
        }
    }

    private static void runScan(String[] args) throws Exception {
        boolean quick = false;
        boolean deep = false;
        boolean autoQuarantine = false;
        Path jsonOut = null;
        List<Path> targets = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--quick" -> quick = true;
                case "--deep" -> deep = true;
                case "--quarantine" -> autoQuarantine = true;
                case "--no-color" -> ConsoleUi.setColorEnabled(false);
                case "--json" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("Missing path after --json");
                    }
                    jsonOut = Path.of(args[++i]);
                }
                default -> targets.add(Path.of(args[i]));
            }
        }

        if (quick || targets.isEmpty()) {
            targets = ThreatScanner.quickScanRoots();
        }
        executeScan(targets, deep, jsonOut, autoQuarantine);
    }

    private static void executeScan(List<Path> targets, boolean deep, Path jsonOut, boolean autoQuarantine) throws Exception {
        ConsoleUi.printBanner(VERSION);
        System.out.println("  Mode       : " + (deep ? "Deep Scan (all files)" : "Smart Scan (executables, scripts, disguised PE)"));
        System.out.println("  Targets    : " + targets.size() + " path(s)");
        for (Path t : targets) {
            System.out.println("    - " + t.toAbsolutePath());
        }
        System.out.println();

        ThreatScanner.ScanSummary summary = ThreatScanner.scanPaths(targets, deep, true);

        System.out.println();
        System.out.println(ConsoleUi.bold("Scan Complete"));
        System.out.println("  Files      : " + summary.totalFiles() + " inspected (" + summary.skippedFiles() + " skipped)");
        System.out.println("  Data       : " + ConsoleUi.formatBytes(summary.totalBytes()));
        System.out.printf(Locale.ROOT, "  Duration   : %.2f s%n", summary.elapsedSeconds());
        System.out.println("  Threats    : " + (summary.findings().isEmpty()
                ? ConsoleUi.green("0 detected")
                : ConsoleUi.red(summary.findings().size() + " detected")));

        for (ThreatScanner.ThreatFinding f : summary.findings()) {
            System.out.println();
            System.out.println("  [" + ConsoleUi.severityBadge(f.score()) + " " + f.score() + "/100] " + f.path());
            System.out.println("    SHA-256  : " + f.sha256());
            for (String r : f.reasons()) {
                System.out.println("    - " + r);
            }
            if (autoQuarantine && f.score() >= 55) {
                QuarantineVault.QuarantineEntry q = QuarantineVault.isolate(f.path(), f.score(), String.join("; ", f.reasons()));
                System.out.println("    " + ConsoleUi.yellow("Quarantined as ID: " + q.id()));
            }
        }

        if (jsonOut != null) {
            ThreatScanner.writeJsonReport(jsonOut, summary);
            System.out.println("\n  Report     : " + jsonOut.toAbsolutePath());
        }
    }

    private static void runAudit(String[] args) {
        for (String a : args) {
            if ("--no-color".equals(a)) {
                ConsoleUi.setColorEnabled(false);
            }
        }
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold("Windows Persistence & System Audit"));
        SystemAuditor.AuditReport report = SystemAuditor.runFullAudit();
        System.out.println("  Checks run : " + report.checksRun());
        System.out.println("  Alerts     : " + (report.alerts().isEmpty()
                ? ConsoleUi.green("0 alerts")
                : ConsoleUi.yellow(report.alerts().size() + " alert(s)")));

        for (SystemAuditor.AuditAlert alert : report.alerts()) {
            String badge = switch (alert.severity()) {
                case "CRITICAL", "HIGH" -> ConsoleUi.red(alert.severity());
                case "SUSPICIOUS" -> ConsoleUi.yellow(alert.severity());
                default -> ConsoleUi.cyan(alert.severity());
            };
            System.out.println("  [" + badge + "] [" + alert.category() + "] " + alert.detail());
        }
    }

    private static void runQuarantine(String[] args) throws Exception {
        List<String> pos = new ArrayList<>();
        for (String a : args) {
            if ("--no-color".equals(a)) {
                ConsoleUi.setColorEnabled(false);
            } else {
                pos.add(a);
            }
        }
        if (pos.isEmpty() || "list".equalsIgnoreCase(pos.get(0))) {
            printQuarantineList(QuarantineVault.list());
            return;
        }
        String sub = pos.get(0).toLowerCase(Locale.ROOT);
        switch (sub) {
            case "isolate" -> {
                if (pos.size() < 2) {
                    throw new IllegalArgumentException("Usage: quarantine isolate <file>");
                }
                Path target = Path.of(pos.get(1));
                ThreatScanner.ThreatFinding f = ThreatScanner.inspectSingleFile(target);
                QuarantineVault.QuarantineEntry q = QuarantineVault.isolate(target, f.score(), String.join("; ", f.reasons()));
                System.out.println(ConsoleUi.green("Quarantined successfully"));
                System.out.println("  ID         : " + q.id());
                System.out.println("  Original   : " + q.originalPath());
                System.out.println("  SHA-256    : " + q.sha256());
            }
            case "restore" -> {
                if (pos.size() < 2) {
                    throw new IllegalArgumentException("Usage: quarantine restore <id> [output-dir]");
                }
                Path override = pos.size() >= 3 ? Path.of(pos.get(2)) : null;
                Path restored = QuarantineVault.restore(pos.get(1), override);
                System.out.println(ConsoleUi.green("Restored to: " + restored.toAbsolutePath()));
            }
            case "delete" -> {
                if (pos.size() < 2) {
                    throw new IllegalArgumentException("Usage: quarantine delete <id>");
                }
                QuarantineVault.deletePermanently(pos.get(1));
                System.out.println(ConsoleUi.green("Deleted permanently: " + pos.get(1)));
            }
            default -> throw new IllegalArgumentException("Unknown quarantine action: " + sub);
        }
    }

    private static void printQuarantineList(List<QuarantineVault.QuarantineEntry> entries) {
        System.out.println(ConsoleUi.bold("Quarantine Vault") + " (" + QuarantineVault.vaultDir() + ")");
        if (entries.isEmpty()) {
            System.out.println("  " + ConsoleUi.dim("Vault is empty."));
            return;
        }
        for (QuarantineVault.QuarantineEntry e : entries) {
            System.out.println("  ID " + ConsoleUi.cyan(e.id())
                    + " | Score " + e.score()
                    + " | " + ConsoleUi.formatBytes(e.sizeBytes())
                    + " | " + e.originalPath());
        }
    }

    private static void runClean(String[] args) {
        boolean apply = false;
        List<Path> custom = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                case "--apply" -> apply = true;
                case "--dry-run" -> apply = false;
                case "--no-color" -> ConsoleUi.setColorEnabled(false);
                default -> custom.add(Path.of(a));
            }
        }
        List<Path> targets = custom.isEmpty() ? PcCleaner.safeTempTargets() : custom;
        PcCleaner.CleanResult result = PcCleaner.clean(targets, apply);
        printCleanResult(result);
    }

    private static void printCleanResult(PcCleaner.CleanResult r) {
        System.out.println(ConsoleUi.bold(r.dryRun() ? "PC Temp Cleaner (Dry Run Preview)" : "PC Temp Cleaner (Applied)"));
        for (Path t : r.targets()) {
            System.out.println("  Target     : " + t);
        }
        System.out.println("  Eligible   : " + r.filesEligible() + " file(s) (" + ConsoleUi.formatBytes(r.bytesReclaimable()) + ")");
        if (!r.dryRun()) {
            System.out.println("  Removed    : " + ConsoleUi.green(r.filesRemoved() + " file(s) (" + ConsoleUi.formatBytes(r.bytesFreed()) + " freed)"));
            System.out.println("  Skipped    : " + r.filesLockedOrSkipped() + " locked/protected file(s)");
        } else {
            System.out.println("  Tip        : Run with --apply to remove unlocked temp files.");
        }
    }

    private static void runBackup(String[] args) throws Exception {
        List<String> pos = new ArrayList<>();
        for (String a : args) {
            if ("--no-color".equals(a)) {
                ConsoleUi.setColorEnabled(false);
            } else {
                pos.add(a);
            }
        }
        if (pos.size() != 2) {
            throw new IllegalArgumentException("Usage: backup <source-path> <output.zip>");
        }
        BackupManager.BackupSummary bs = BackupManager.createBackup(Path.of(pos.get(0)), Path.of(pos.get(1)));
        printBackupSummary(bs);
    }

    private static void printBackupSummary(BackupManager.BackupSummary bs) {
        System.out.println(ConsoleUi.bold(ConsoleUi.green("Backup created successfully")));
        System.out.println("  Archive    : " + bs.archivePath());
        System.out.println("  Files      : " + bs.fileCount());
        System.out.println("  Raw size   : " + ConsoleUi.formatBytes(bs.rawBytes()));
        System.out.println("  ZIP size   : " + ConsoleUi.formatBytes(bs.archiveBytes()));
        System.out.println("  Integrity  : Embedded SHA-256 manifest");
    }

    private static void runVerify(String[] args) throws Exception {
        List<String> pos = new ArrayList<>();
        for (String a : args) {
            if ("--no-color".equals(a)) {
                ConsoleUi.setColorEnabled(false);
            } else {
                pos.add(a);
            }
        }
        if (pos.size() != 1) {
            throw new IllegalArgumentException("Usage: verify <backup.zip>");
        }
        BackupManager.VerifySummary vs = BackupManager.verifyBackup(Path.of(pos.get(0)));
        printVerifySummary(vs);
        if (!vs.isOk()) {
            System.exit(2);
        }
    }

    private static void printVerifySummary(BackupManager.VerifySummary vs) {
        System.out.println(ConsoleUi.bold("Backup Integrity Check"));
        System.out.println("  Checked    : " + vs.checkedFiles());
        System.out.println("  Valid      : " + ConsoleUi.green(String.valueOf(vs.validFiles())));
        System.out.println("  Corrupted  : " + (vs.corruptedFiles() == 0 ? "0" : ConsoleUi.red(String.valueOf(vs.corruptedFiles()))));
        System.out.println("  Missing    : " + (vs.missingFiles() == 0 ? "0" : ConsoleUi.red(String.valueOf(vs.missingFiles()))));
        System.out.println("  Status     : " + (vs.isOk() ? ConsoleUi.green("VERIFIED OK") : ConsoleUi.red("FAILED")));
    }

    private static void runRestore(String[] args) throws Exception {
        List<String> pos = new ArrayList<>();
        for (String a : args) {
            if ("--no-color".equals(a)) {
                ConsoleUi.setColorEnabled(false);
            } else {
                pos.add(a);
            }
        }
        if (pos.size() != 2) {
            throw new IllegalArgumentException("Usage: restore <backup.zip> <destination-dir>");
        }
        int restored = BackupManager.restoreBackup(Path.of(pos.get(0)), Path.of(pos.get(1)));
        System.out.println(ConsoleUi.green("Restored " + restored + " file(s) to " + Path.of(pos.get(1)).toAbsolutePath()));
    }

    private static void printUsage() {
        ConsoleUi.printBanner(VERSION);
        System.out.println("Usage (run with no arguments for interactive menu):");
        System.out.println("  java -jar aegiscore.jar scan [--quick | <path>...] [--deep] [--quarantine] [--json <report.json>]");
        System.out.println("  java -jar aegiscore.jar audit");
        System.out.println("  java -jar aegiscore.jar quarantine [list | isolate <file> | restore <id> [dir] | delete <id>]");
        System.out.println("  java -jar aegiscore.jar clean [--dry-run | --apply]");
        System.out.println("  java -jar aegiscore.jar backup <source-dir> <output.zip>");
        System.out.println("  java -jar aegiscore.jar verify <backup.zip>");
        System.out.println("  java -jar aegiscore.jar restore <backup.zip> <dest-dir>");
    }
}
