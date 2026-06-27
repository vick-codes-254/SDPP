/** MITRE ATT&CK tactic matrix — count heatmap across tactics.
 *  Inspired by Splunk Enterprise Security "MITRE ATT&CK Techniques by Risk Object". */

const TACTICS: { key: string; label: string; techniques: string[] }[] = [
  { key: "initial_access", label: "Initial Access", techniques: ["Suspicious login", "New device", "Impossible travel"] },
  { key: "execution", label: "Execution", techniques: ["API abuse"] },
  { key: "persistence", label: "Persistence", techniques: ["Account manipulation"] },
  { key: "privilege_escalation", label: "Priv. Escalation", techniques: ["Privilege escalation"] },
  { key: "defense_evasion", label: "Defense Evasion", techniques: ["Session anomaly"] },
  { key: "credential_access", label: "Credential Access", techniques: ["Brute force", "Failed login"] },
  { key: "discovery", label: "Discovery", techniques: ["Network scan"] },
  { key: "lateral_movement", label: "Lateral Movement", techniques: ["Remote services"] },
  { key: "collection", label: "Collection", techniques: ["Data staged"] },
  { key: "command_control", label: "C2", techniques: ["Beaconing"] },
  { key: "exfiltration", label: "Exfiltration", techniques: ["API abuse"] },
  { key: "impact", label: "Impact", techniques: ["Account lockout"] },
];

/** Maps a cyber-event type to a MITRE tactic key. */
export const CYBER_TO_TACTIC: Record<string, string> = {
  suspicious_login: "initial_access",
  new_device: "initial_access",
  impossible_travel: "initial_access",
  api_abuse: "exfiltration",
  privilege_escalation: "privilege_escalation",
  session_anomaly: "defense_evasion",
  brute_force: "credential_access",
  failed_login: "credential_access",
  account_lockout: "impact",
};

function heat(count: number, max: number): { bg: string; fg: string } {
  if (count === 0) return { bg: "transparent", fg: "var(--text-3, #6F7889)" };
  const t = max ? count / max : 0;
  const color =
    t > 0.75 ? "var(--sev-critical)" :
    t > 0.5 ? "var(--sev-high)" :
    t > 0.25 ? "var(--sev-medium)" : "var(--sev-low)";
  return { bg: `color-mix(in srgb, ${color} ${Math.round(25 + t * 45)}%, transparent)`, fg: "#fff" };
}

export function MitreMatrix({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="overflow-x-auto">
      <div className="flex min-w-[840px] gap-2">
        {TACTICS.map((t) => {
          const c = counts[t.key] ?? 0;
          const h = heat(c, max);
          return (
            <div key={t.key} className="flex w-[110px] shrink-0 flex-col">
              <div className="label-micro mb-1 h-8 leading-tight text-muted-foreground">{t.label}</div>
              <div
                className="flex h-12 items-center justify-center rounded-md border border-border text-lg font-semibold tabular-nums"
                style={{ background: h.bg, color: c ? h.fg : "var(--muted-foreground)" }}
              >
                {c}
              </div>
              <div className="mt-1 space-y-0.5">
                {t.techniques.map((tech) => (
                  <div key={tech} className="truncate rounded bg-card px-1.5 py-0.5 text-[10px] text-muted-foreground" title={tech}>
                    {tech}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
