package com.dips.aegiscore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

public final class SystemAuditor {
    public record AuditAlert(String category, String severity, String detail) {
    }

    public record AuditReport(int checksRun, List<AuditAlert> alerts) {
    }

    private SystemAuditor() {
    }

    public static AuditReport runFullAudit() {
        List<AuditAlert> alerts = new ArrayList<>();
        int checks = 0;

        checks++;
        auditHostsFile(alerts);

        checks++;
        auditStartupFolders(alerts);

        if (isWindows()) {
            checks++;
            auditRegistryRunKey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", alerts);
            checks++;
            auditRegistryRunKey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", alerts);
            checks++;
            auditRegistryRunKey("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", alerts);
            checks++;
            auditRunningProcesses(alerts);
        }

        return new AuditReport(checks, alerts);
    }

    private static void auditHostsFile(List<AuditAlert> alerts) {
        Path hosts = isWindows()
                ? Path.of("C:\\Windows\\System32\\drivers\\etc\\hosts")
                : Path.of("/etc/hosts");
        if (!Files.isRegularFile(hosts)) {
            return;
        }
        try {
            List<String> lines = Files.readAllLines(hosts, StandardCharsets.UTF_8);
            for (String raw : lines) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.endsWith("localhost") || lower.contains("broadcasthost") || lower.contains("ip6-")) {
                    continue;
                }
                if (lower.contains("virustotal") || lower.contains("malwarebytes") || lower.contains("kaspersky")
                        || lower.contains("windowsupdate") || lower.contains("defender") || lower.contains("microsoft.com")) {
                    alerts.add(new AuditAlert("HOSTS", "HIGH", "Security domain redirected/blocked in hosts: " + line));
                } else {
                    alerts.add(new AuditAlert("HOSTS", "LOW", "Custom hosts entry: " + line));
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void auditStartupFolders(List<AuditAlert> alerts) {
        List<Path> dirs = new ArrayList<>();
        String home = System.getProperty("user.home");
        if (home != null) {
            dirs.add(Path.of(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }
        String programData = System.getenv("ProgramData");
        if (programData != null) {
            dirs.add(Path.of(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }

        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> s = Files.list(dir)) {
                for (Path p : s.toList()) {
                    String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                    if ("desktop.ini".equals(name)) {
                        continue;
                    }
                    if (name.endsWith(".vbs") || name.endsWith(".ps1") || name.endsWith(".bat")
                            || name.endsWith(".cmd") || name.endsWith(".hta") || name.endsWith(".js")) {
                        alerts.add(new AuditAlert("STARTUP", "HIGH", "Script in Windows Startup folder: " + p));
                    } else if (name.endsWith(".exe") || name.endsWith(".scr")) {
                        alerts.add(new AuditAlert("STARTUP", "SUSPICIOUS", "Executable directly in Startup folder: " + p));
                    }
                }
            } catch (IOException ignored) {
            }
        }
    }

    private static void auditRegistryRunKey(String keyPath, List<AuditAlert> alerts) {
        List<String> lines = execLines("reg", "query", keyPath);
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("HKEY_") || trimmed.startsWith("ERROR:")) {
                continue;
            }
            String lower = trimmed.toLowerCase(Locale.ROOT);
            if (lower.contains("\\temp\\") || lower.contains("powershell") || lower.contains("mshta")
                    || lower.contains("wscript") || lower.contains("cscript") || lower.contains("regsvr32")
                    || lower.contains("cmd /c") || lower.contains("-enc ")) {
                alerts.add(new AuditAlert("REGISTRY", "HIGH", keyPath + " -> " + trimmed));
            }
        }
    }

    private static void auditRunningProcesses(List<AuditAlert> alerts) {
        List<String> lines = execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)|$($_.Name)|$($_.ExecutablePath)|$($_.CommandLine)\" }"
        );
        for (String line : lines) {
            String lower = line.toLowerCase(Locale.ROOT);
            String[] parts = line.split("\\|", 4);
            if (parts.length < 4) {
                continue;
            }
            String pid = parts[0];
            String name = parts[1];
            String exePath = parts[2];
            String cmd = parts[3];

            if (exePath.toLowerCase(Locale.ROOT).contains("\\appdata\\local\\temp\\")
                    || exePath.toLowerCase(Locale.ROOT).contains("\\windows\\temp\\")) {
                alerts.add(new AuditAlert("PROCESS", "HIGH", "PID " + pid + " (" + name + ") running from Temp: " + exePath));
            } else if ((name.equalsIgnoreCase("powershell.exe") || name.equalsIgnoreCase("pwsh.exe"))
                    && (lower.contains(" -enc ") || lower.contains("-encodedcommand") || lower.contains("downloadstring"))) {
                alerts.add(new AuditAlert("PROCESS", "CRITICAL", "PID " + pid + " suspicious PowerShell command: " + cmd));
            }
        }
    }

    private static List<String> execLines(String... cmd) {
        List<String> out = new ArrayList<>();
        try {
            Process proc = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    out.add(line);
                }
            }
            proc.waitFor(8, TimeUnit.SECONDS);
        } catch (Exception ignored) {
        }
        return out;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
