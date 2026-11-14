import { api } from "../api";

export const POLL_MS = 3000;

export async function waitJob(id, alive) {
  for (;;) {
    if (!alive()) return null;
    const res = await api.get(`/jobs/${id}`);
    const job = res.data.job;
    if (job.status === "done" || job.status === "error") return job;
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

export const isRunning = (job) => job?.status === "pending" || job?.status === "running";
