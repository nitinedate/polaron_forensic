/** IPv4 CIDR helpers for network-scoped scanner tokens. */

function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    n = (n << 8) + octet;
  }
  return n >>> 0;
}

export function parseIpv4Cidr(cidr: string): { base: number; mask: number; text: string } | null {
  const raw = cidr.trim();
  const [ipPart, bitsPart] = raw.split("/");
  const ip = ipv4ToInt(ipPart || "");
  const bits = bitsPart === undefined || bitsPart === "" ? 32 : Number(bitsPart);
  if (ip === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  return { base: ip & mask, mask, text: raw };
}

export function ipInCidr(ipOrCidr: string, cidr: string): boolean {
  const net = parseIpv4Cidr(cidr);
  if (!net) return false;
  const value = ipOrCidr.trim();
  if (value.includes("/")) {
    const other = parseIpv4Cidr(value);
    if (!other) return false;
    return (other.base & net.mask) === net.base && other.mask >= net.mask;
  }
  const ip = ipv4ToInt(value);
  if (ip === null) return false;
  return (ip & net.mask) === net.base;
}

export function targetsOutsideCidr(targets: string[], cidr: string): string[] {
  return targets.filter((t) => t && !ipInCidr(t, cidr));
}
