// The attacks the simulator can write. The ids match the backend's scenario names.
export const SCENARIOS = [
  {
    id: 'full_chain',
    label: 'Full attack chain',
    description: 'Phishing, PowerShell, privilege escalation and exfiltration, in order, on one machine.',
  },
  {
    id: 'brute_force',
    label: 'Brute force login',
    description: '40 failed logons on one account in two minutes, then one success.',
  },
  {
    id: 'phishing',
    label: 'Phishing',
    description: 'An email from a lookalike domain with a macro attachment, then Word starting a command shell.',
  },
  {
    id: 'powershell',
    label: 'Malicious PowerShell',
    description: 'PowerShell started with a hidden, encoded command that downloads a file.',
  },
  {
    id: 'privilege_escalation',
    label: 'Privilege escalation',
    description: 'A new local account is created and added to the Administrators group.',
  },
  {
    id: 'exfiltration',
    label: 'Data exfiltration',
    description: 'A workstation uploads about 2 GB to an outside address over FTP.',
  },
]

export function scenarioLabel(id: string) {
  return SCENARIOS.find((scenario) => scenario.id === id)?.label ?? 'Background'
}
