import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import ScanDetails from "../ScanDetails";
import Dashboard from "../Dashboard";
import { api, getIgnored, getRules } from "../../api";

jest.mock("../../api", () => ({
  api: {
    get: jest.fn(),
    post: jest.fn(),
  },
  getIgnored: jest.fn(),
  getRules: jest.fn(),
  fixRule: jest.fn(),
  ignoreRule: jest.fn(),
  unignoreRule: jest.fn(),
  scanSingleRule: jest.fn(),
}));

function mockScan(res) {
  api.post.mockResolvedValueOnce({ data: { job: { id: 1, status: "pending", server_id: 1 }, started: true } });
  const prev = api.get.getMockImplementation();
  api.get.mockImplementation((url, config) => {
    if (url === "/jobs/1") return Promise.resolve({ data: { job: { id: 1, status: "done", server_id: 1, result: res.data } } });
    return prev(url, config);
  });
}

describe("ScanDetails Bileşeni", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
    api.get.mockImplementation((url) => {
      if (url.includes("scheduler/alerts")) {
        return Promise.resolve({ data: { alerts: [] } });
      }
      return Promise.resolve({ data: {} });
    });
  });

  test("başlangıç durumu render edilmeli", () => {
    render(<ScanDetails />);

    expect(screen.getByText("Güvenlik Taraması")).toBeInTheDocument();
    expect(screen.getByText("Taramayı Başlat")).toBeInTheDocument();
    expect(screen.getByText("PDF Rapor")).toBeInTheDocument();
  });

  test("boş durum mesajı gösterilmeli", () => {
    render(<ScanDetails />);

    expect(screen.getByText(/Sistem analizini başlatmak için/)).toBeInTheDocument();
  });

  test("tarama butonu tıklanmalı", async () => {
    mockScan({
      data: {
        results: [
          { id: "rule1", name: "Test Kuralı", status: "ok", severity: "low", category: "Test", description: "Test" },
        ],
        summary: { total: 1, warnings: 0, ok: 1 },
      },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    render(<ScanDetails />);

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith("/jobs", { kind: "scan", server_id: 1 });
    });
  });

  test("tarama sonuçları gösterilmeli", async () => {
    mockScan({
      data: {
        results: [
          { id: "rule1", name: "Güvenli Kural", status: "ok", severity: "low", category: "Test", description: "Test" },
          { id: "rule2", name: "Sorunlu Kural", status: "warning", severity: "high", category: "Test", description: "Test Uyarı", output: "Hata" },
        ],
        summary: { total: 2, warnings: 1, ok: 1 },
      },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    render(<ScanDetails />);

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(screen.getByText(/Toplam:\s*2\s*kural/)).toBeInTheDocument();
      expect(screen.getByText(/Uyarı\s*\(1\)/)).toBeInTheDocument();
      expect(screen.getAllByText(/Güvenli/).length).toBeGreaterThan(0);
    });
  });

  test("düzeltme butonu çalışmalı", async () => {
    const { fixRule } = require("../../api");
    fixRule.mockResolvedValueOnce({ data: { message: "Düzeltme başarılı" } });

    mockScan({
      data: {
        results: [
          { id: "rule1", name: "Test Kuralı", status: "warning", severity: "medium", category: "Test", description: "Test" },
        ],
        summary: { total: 1, warnings: 1, ok: 0 },
      },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    render(<ScanDetails />);

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(screen.getByText("Düzelt")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Düzelt"));

    await waitFor(() => {
      expect(fixRule).toHaveBeenCalledWith("rule1");
    });
  });

  test("görmezden gelme çalışmalı", async () => {
    const { ignoreRule } = require("../../api");
    ignoreRule.mockResolvedValueOnce({ data: { success: true } });

    mockScan({
      data: {
        results: [
          { id: "rule1", name: "Test Kuralı", status: "warning", severity: "medium", category: "Test", description: "Test" },
        ],
        summary: { total: 1, warnings: 1, ok: 0 },
      },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    render(<ScanDetails />);

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(screen.getByText("Görmezden Gel")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Görmezden Gel"));

    await waitFor(() => {
      expect(ignoreRule).toHaveBeenCalledWith("rule1");
    });
  });

  test("filtreleme çalışmalı", async () => {
    mockScan({
      data: {
        results: [
          { id: "rule1", name: "Güvenli Kural", status: "ok", severity: "low", category: "Test", description: "Test" },
          { id: "rule2", name: "Sorunlu Kural", status: "warning", severity: "high", category: "Test", description: "Test" },
        ],
        summary: { total: 2, warnings: 1, ok: 1 },
      },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    render(<ScanDetails />);

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(screen.getByText("Uyarılar")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Uyarılar"));

    await waitFor(() => {
      expect(screen.getByText("Sorunlu Kural")).toBeInTheDocument();
      expect(screen.queryByText("Güvenli Kural")).not.toBeInTheDocument();
    });
  });

  test("PDF indirme butonu çalışmalı", async () => {
    const mockBlob = new Blob(["test"], { type: "application/pdf" });
    api.get.mockImplementation((url, config) => {
      if (url === "/report/pdf") {
        return Promise.resolve({ data: mockBlob });
      }
      return Promise.resolve({ data: { alerts: [] } });
    });

    global.URL.createObjectURL = jest.fn(() => "blob:test");
    global.URL.revokeObjectURL = jest.fn();

    render(<ScanDetails />);

    mockScan({
      data: { results: [], summary: { total: 0, warnings: 0, ok: 0 } },
    });
    getIgnored.mockResolvedValueOnce({ data: { ignored: [] } });
    getRules.mockResolvedValueOnce({ data: { rules: [] } });

    fireEvent.click(screen.getByText("Taramayı Başlat"));

    await waitFor(() => {
      expect(screen.getByText("PDF Rapor")).not.toBeDisabled();
    });
  });
});

describe("Dashboard Bileşeni", () => {
  test("Dashboard verileri yükleyip Kontrol Paneli başlığını render etmeli", async () => {
    api.get.mockImplementation((url) => {
      if (url.includes("/servers")) {
        return Promise.resolve({ data: { servers: [{ id: 1, name: "Yerel Sunucu", ip_address: "127.0.0.1", port: 8000, status: "online" }] } });
      }
      if (url.includes("/history/trend")) {
        return Promise.resolve({ data: { trend: [{ score: 85, created_at: "2026-10-18T00:00:00" }] } });
      }
      if (url.includes("/history/scans")) {
        return Promise.resolve({ data: { history: [{ total: 50, warnings: 2, ok_count: 48, score: 96, created_at: "2026-10-18T00:00:00" }] } });
      }
      if (url.includes("/scheduler/alerts")) {
        return Promise.resolve({ data: { alerts: [] } });
      }
      if (url.includes("/ignored")) {
        return Promise.resolve({ data: { ignored: [] } });
      }
      if (url.includes("/scheduler/config")) {
        return Promise.resolve({ data: { enabled: true, interval: "weekly", hour: 3, minute: 0 } });
      }
      return Promise.resolve({ data: {} });
    });

    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText("Kontrol Paneli")).toBeInTheDocument();
    });
  });
});

