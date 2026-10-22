import type { ProcessScenario } from "../../domain/process/processScenario.js";

interface ProcessCaptureEnvironmentOptions {
  readonly scenario: ProcessScenario;
  readonly runId: string;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
}

export const ALLOWED_PROCESS_CAPTURE_ENVIRONMENT_KEYS = [
  "DBUS_SESSION_BUS_ADDRESS",
  "DISPLAY",
  "HOME",
  "LANG",
  "LC_ALL",
  "LD_LIBRARY_PATH",
  "PATH",
  "SystemRoot",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "XDG_RUNTIME_DIR",
] as const;

/** Build the child environment from the host allowlist plus caller-selected overrides. */
export const makeProcessCaptureEnvironment = (
  options: ProcessCaptureEnvironmentOptions,
): Record<string, string> => ({
  ...Object.fromEntries(
    ALLOWED_PROCESS_CAPTURE_ENVIRONMENT_KEYS.map(
      (name) => [name, options.hostEnvironment[name]] as const,
    ).filter((entry): entry is [string, string] => entry[1] !== undefined),
  ),
  ...options.scenario.environment,
  TERM:
    options.scenario.environment.TERM ??
    options.hostEnvironment.TERM ??
    "xterm-256color",
  REA_PROCESS_RUN_ID: options.runId,
});
