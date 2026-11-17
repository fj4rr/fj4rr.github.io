// Profile and site-wide settings. Edit this file to update your name, bio and links.
export const SITE = {
  name: 'fj4rr_',
  title: 'fj4rr_ — Malware Analysis & Threat Research',
  description:
    'Malware analysis reports, reverse engineering research, cybersecurity projects and technical tutorials by fj4rr_.',
  url: 'https://fj4rr.github.io',
  locale: 'en',
};

export const PROFILE = {
  handle: 'fj4rr_',
  intro: 'A cybersecurity analyst who is interested in malware analysis, reverse engineering, and threat intelligence.',
  // HTML allowed (rendered with set:html on the About page)
  background: [
    'Outside work, I\'m also trying to develop (with AI assistance) some tools that hopefully make cyber defense work a bit easier, like <a href="/projects/jatmp/">JATMP</a> (don\'t forget to check it out).',
  ],
  interests: ['Malware analysis', 'Reverse engineering', 'Threat intelligence', 'Windows internals', 'Detection engineering', 'Security tooling'],
  // Skills shown here are taken from the published work (report tooling and project stack).
  skills: [
    { group: 'Analysis', items: ['Static analysis', 'Dynamic analysis', 'C2 protocol analysis', 'IOC extraction', 'MITRE ATT&CK mapping', 'YARA'] },
    { group: 'Tooling', items: ['IDA Pro', 'FLARE-VM', 'REMnux', 'Sysmon / Procmon', 'PCAP analysis'] },
    { group: 'Engineering', items: ['Python', 'STIX / TAXII', 'MISP'] },
  ],
  links: [
    { label: 'GitHub', href: 'https://github.com/fj4rr', handle: '@fj4rr' },
    { label: 'LinkedIn', href: 'https://www.linkedin.com/in/mffajari/', handle: 'in/mffajari' },
    { label: 'Medium', href: 'https://mffajari.medium.com/', handle: '@mffajari' },
  ],
};

export const NAV = [
  { label: 'Blog', href: '/blog/' },
  { label: 'Projects', href: '/projects/' },
  { label: 'About', href: '/about/' },
];
