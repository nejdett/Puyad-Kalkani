import React from "react";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import "@testing-library/jest-dom";
import ScanDetails from "../ScanDetails";
import { api, getIgnored, getRules } from "../../api";

jest.mock("../../api", () => ({
  api: { get: jest.fn(), post: jest.fn() },
  scanSystem: jest.fn(),
  fixRule: jest.fn(),
  ignoreRule: jest.fn(),
  unignoreRule: jest.fn(),
  getIgnored: jest.fn(),
  getRules: jest.fn(),
  scanSingleRule: jest.fn(),
}));

const CACHE = {
  results: [{ id: "1.1", name: "Önbellekteki Kural", status: "ok", category: "ssh" }],
  summary: { total: 1, warnings: 0, ok: 1, score: 100, scan_id: 7 },
  ignoredRules: [],
  ts: Date.now(),
};

function mockHistory(ids) {
  api.get.mockImplementation((url) => {
    if (url === "/history/scans") return Promise.resolve({ data: { history: ids.map((id) => ({ id })) } });
    return Promise.resolve({ data: { servers: [] } });
  });
}

describe("ScanDetails önbellek", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.setItem("puyad_scan_cache", JSON.stringify(CACHE));
  });

  test("veritabanında olmayan tarama önbellekten silinir", async () => {
    mockHistory([]);
    render(<ScanDetails />);
    await waitFor(() => expect(localStorage.getItem("puyad_scan_cache")).toBeNull());
    expect(screen.queryByText("Önbellekteki Kural")).not.toBeInTheDocument();
  });

  test("veritabanında olan tarama korunur", async () => {
    mockHistory([7, 6]);
    render(<ScanDetails />);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/history/scans", { params: { limit: 200 } }));
    expect(localStorage.getItem("puyad_scan_cache")).not.toBeNull();
    expect(screen.getByText("Önbellekteki Kural")).toBeInTheDocument();
  });
});

const NEW_RESULT = {
  results: [{ id: "2.1", name: "Yeni Kural", status: "ok", category: "ssh" }],
  summary: { total: 1, warnings: 0, ok: 1, score: 100, scan_id: 8 },
};

function mockJobs(current, polls = []) {
  api.get.mockImplementation((url) => {
    if (url === "/history/scans") return Promise.resolve({ data: { history: [{ id: 7 }, { id: 8 }] } });
    if (url === "/jobs/current") return Promise.resolve({ data: { job: current } });
    if (url.startsWith("/jobs/")) return Promise.resolve({ data: { job: polls.length > 1 ? polls.shift() : polls[0] } });
    return Promise.resolve({ data: { servers: [] } });
  });
}

describe("ScanDetails tarama işi", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.setItem("puyad_scan_cache", JSON.stringify(CACHE));
    getIgnored.mockResolvedValue({ data: { ignored: [] } });
    getRules.mockResolvedValue({ data: { rules: [] } });
  });

  afterEach(() => jest.useRealTimers());

  test("süren iş geri dönünce takip edilir", async () => {
    jest.useFakeTimers();
    const job = { id: 9, server_id: 1, status: "running" };
    mockJobs(job, [job, { ...job, status: "done", result: NEW_RESULT }]);
    render(<ScanDetails />);
    expect(await screen.findByText("Taranıyor...")).toBeInTheDocument();
    expect(screen.queryByText("Yeni Kural")).not.toBeInTheDocument();
    await act(async () => { jest.advanceTimersByTime(3000); });
    expect(await screen.findByText("Yeni Kural")).toBeInTheDocument();
    expect(screen.getByText("Taramayı Başlat")).toBeInTheDocument();
  });

  test("sayfa kapalıyken biten iş gösterilir", async () => {
    mockJobs({ id: 9, server_id: 1, status: "done", result: NEW_RESULT });
    render(<ScanDetails />);
    expect(await screen.findByText("Yeni Kural")).toBeInTheDocument();
    expect(screen.queryByText("Önbellekteki Kural")).not.toBeInTheDocument();
  });

  test("önbellekteki iş yeniden uygulanmaz", async () => {
    const old = { ...NEW_RESULT, summary: { ...NEW_RESULT.summary, scan_id: 7 } };
    mockJobs({ id: 9, server_id: 1, status: "done", result: old });
    render(<ScanDetails />);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/jobs/current", { params: { kind: "scan" } }));
    expect(screen.getByText("Önbellekteki Kural")).toBeInTheDocument();
    expect(screen.queryByText("Yeni Kural")).not.toBeInTheDocument();
  });

  test("hatalı iş mesaj gösterir", async () => {
    mockJobs(null, [{ id: 3, server_id: 1, status: "error", error: "Uzak tarama başarısız" }]);
    api.post.mockResolvedValue({ data: { job: { id: 3, server_id: 1, status: "pending" }, started: true } });
    render(<ScanDetails />);
    fireEvent.click(screen.getByText("Taramayı Başlat"));
    expect(await screen.findByText(/Uzak tarama başarısız/)).toBeInTheDocument();
  });

  test("başka sunucuda süren tarama takip edilmez", async () => {
    mockJobs(null);
    api.post.mockResolvedValue({ data: { job: { id: 3, server_id: 2, status: "running" }, started: false } });
    render(<ScanDetails />);
    fireEvent.click(screen.getByText("Taramayı Başlat"));
    expect(await screen.findByText(/Başka bir sunucuda tarama sürüyor/)).toBeInTheDocument();
    expect(api.get).not.toHaveBeenCalledWith("/jobs/3");
    expect(screen.getByText("Önbellekteki Kural")).toBeInTheDocument();
  });
});
