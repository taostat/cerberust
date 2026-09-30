import { useEffect, useState } from "react";

type Subnet = { netuid: number; name: string; owner: string; emission: string };

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "https://api.example.com";

export async function fetchSubnets(signal?: AbortSignal): Promise<Subnet[]> {
  const res = await fetch(`${API_BASE}/v1/subnets?limit=100`, {
    headers: { Authorization: `Bearer ${process.env.API_KEY}`, "Content-Type": "application/json" },
    signal,
  });
  if (!res.ok) throw new Error(`subnets request failed: ${res.status}`);
  return (await res.json()).data as Subnet[];
}

export function SubnetList() {
  const [subnets, setSubnets] = useState<Subnet[]>([]);
  useEffect(() => {
    const controller = new AbortController();
    fetchSubnets(controller.signal).then(setSubnets).catch(console.error);
    return () => controller.abort();
  }, []);
  return subnets.map((s) => <div key={s.netuid}>{s.name} — {s.owner}</div>);
}

export const FEATURE_FLAGS = { newDashboard: true, chartVersion: 3 };
export const OWNER_EXAMPLE = "5WLGF5ckdYzEqx8EiVFSLvXT58Gng8a1due5UZrcodGnoeYd";
export const SESSION_EXAMPLE_ID = "616670c2-45d4-4b2c-80f0-272cdf1d2629";
