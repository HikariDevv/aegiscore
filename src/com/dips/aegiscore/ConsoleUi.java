package com.dips.aegiscore;

import java.util.Locale;

public final class ConsoleUi {
    private static boolean colorEnabled = System.getenv("NO_COLOR") == null;

    private ConsoleUi() {
    }

    public static void setColorEnabled(boolean enabled) {
        colorEnabled = enabled;
    }

    public static String bold(String s) {
        return wrap("1", s);
    }

    public static String dim(String s) {
        return wrap("2", s);
    }

    public static String green(String s) {
        return wrap("32", s);
    }

    public static String yellow(String s) {
        return wrap("33", s);
    }

    public static String red(String s) {
        return wrap("31", s);
    }

    public static String cyan(String s) {
        return wrap("36", s);
    }

    public static String magenta(String s) {
        return wrap("35", s);
    }

    public static String severityBadge(int score) {
        if (score >= 80) {
            return bold(red("CRITICAL"));
        }
        if (score >= 55) {
            return bold(red("HIGH"));
        }
        if (score >= 30) {
            return bold(yellow("SUSPICIOUS"));
        }
        if (score > 0) {
            return cyan("LOW");
        }
        return green("CLEAN");
    }

    public static String severityLabel(int score) {
        if (score >= 80) {
            return "CRITICAL";
        }
        if (score >= 55) {
            return "HIGH";
        }
        if (score >= 30) {
            return "SUSPICIOUS";
        }
        if (score > 0) {
            return "LOW";
        }
        return "CLEAN";
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024.0) {
            return String.format(Locale.ROOT, "%.2f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024.0) {
            return String.format(Locale.ROOT, "%.2f MB", mb);
        }
        double gb = mb / 1024.0;
        return String.format(Locale.ROOT, "%.2f GB", gb);
    }

    public static void printBanner(String version) {
        System.out.println(bold(cyan("========================================================")));
        System.out.println(bold(cyan("  AEGISCORE v" + version)) + dim("  |  PC Security, Scanner & Backup Suite"));
        System.out.println(bold(cyan("========================================================")));
    }

    private static String wrap(String code, String text) {
        if (!colorEnabled) {
            return text;
        }
        return "\u001B[" + code + "m" + text + "\u001B[0m";
    }
}
