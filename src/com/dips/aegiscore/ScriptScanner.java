package com.dips.aegiscore;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class ScriptScanner {
    private static final Set<String> SCRIPT_EXTS = Set.of(
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".py", ".sh", ".reg"
    );

    private static final Pattern DOUBLE_EXT = Pattern.compile(
            ".*\\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|mp3|mp4|txt|zip)\\.(exe|scr|bat|cmd|vbs|js|ps1|hta|com|pif)$"
    );

    private static final Pattern PS_ENCODED = Pattern.compile(
            "(powershell|pwsh)[^\\n]{0,120}(-(e|ec|enc|encodedcommand)\\s+[a-z0-9+/=]{24,}|frombase64string)"
    );

    private static final Pattern DOWNLOAD_EXEC = Pattern.compile(
            "(invoke-webrequest|iwr|downloadstring|downloadfile|bitsadmin|certutil\\s+-urlcache|curl\\s+[^\\n]{0,120}\\|\\s*(sh|bash|iex))"
    );

    private static final Pattern DEFENDER_TAMPER = Pattern.compile(
            "(add-mppreference|set-mppreference|disablerealtimemonitoring|sc\\s+stop\\s+windefend|net\\s+stop\\s+windefend)"
    );

    private static final Pattern RANSOM_RECOVERY = Pattern.compile(
            "(vssadmin\\s+delete\\s+shadows|wmic\\s+shadowcopy\\s+delete|wbadmin\\s+delete\\s+catalog|bcdedit\\s+/set\\s+\\{default\\}\\s+recoveryenabled\\s+no)"
    );

    private static final Pattern PERSISTENCE = Pattern.compile(
            "(currentversion\\\\run|schtasks\\s+/create|new-scheduledtask|reg\\s+add\\s+[^\\n]{0,100}\\\\run)"
    );

    private static final Pattern EXFIL = Pattern.compile(
            "(discord(app)?\\.com/api/webhooks/|api\\.telegram\\.org/bot[0-9]+:)"
    );

    public record ScriptResult(int score, List<String> findings) {
    }

    private ScriptScanner() {
    }

    public static boolean isScriptExtension(String lowerName) {
        for (String ext : SCRIPT_EXTS) {
            if (lowerName.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    public static boolean hasDoubleExtension(String lowerName) {
        return DOUBLE_EXT.matcher(lowerName).matches();
    }

    public static ScriptResult analyze(byte[] data, String lowerName) {
        List<String> findings = new ArrayList<>();
        int score = 0;

        if (hasDoubleExtension(lowerName)) {
            score += 45;
            findings.add("Deceptive double file extension detected");
        }

        if (!isScriptExtension(lowerName)) {
            return new ScriptResult(score, findings);
        }

        String text = new String(data, 0, Math.min(data.length, 512 * 1024), StandardCharsets.UTF_8)
                .toLowerCase(Locale.ROOT);

        if (PS_ENCODED.matcher(text).find()) {
            score += 45;
            findings.add("Encoded/obfuscated PowerShell execution pattern");
        }
        if (DOWNLOAD_EXEC.matcher(text).find()) {
            score += 30;
            findings.add("Remote payload download/execution command");
        }
        if (text.contains("invoke-expression") || text.contains("iex(") || text.contains("iex ")) {
            score += 20;
            findings.add("Dynamic script evaluation (IEX / Invoke-Expression)");
        }
        if (DEFENDER_TAMPER.matcher(text).find()) {
            score += 45;
            findings.add("Windows Defender disabling or exclusion command");
        }
        if (RANSOM_RECOVERY.matcher(text).find()) {
            score += 55;
            findings.add("Shadow copy / Windows recovery deletion command");
        }
        if (PERSISTENCE.matcher(text).find()) {
            score += 25;
            findings.add("Windows persistence mechanism (Run key / Scheduled Task)");
        }
        if (EXFIL.matcher(text).find()) {
            score += 35;
            findings.add("Embedded webhook/bot exfiltration endpoint");
        }
        if (text.contains("wscript.shell") && (text.contains("powershell") || text.contains("cmd.exe"))) {
            score += 30;
            findings.add("WScript.Shell spawning hidden shell");
        }

        return new ScriptResult(Math.min(100, score), findings);
    }
}
