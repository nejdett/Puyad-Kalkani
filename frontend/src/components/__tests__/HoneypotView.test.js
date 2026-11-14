import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import HoneypotView from "../HoneypotView";
import { api } from "../../api";

jest.mock("../../api", () => ({
  api: {
    get: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
  },
}));

describe("HoneypotView Bileşeni", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/honeypot/active") {
        return Promise.resolve({
          data: {
            pots: [
              { port: 21, service: "ftp", label: "FTP Tuzağı", active: true },
            ],
          },
        });
      }
      if (url.startsWith("/honeypot/hits")) {
        return Promise.resolve({ data: { hits: [] } });
      }
      if (url.startsWith("/honeypot/check-port/")) {
        const p = parseInt(url.split("/").pop(), 10);
        if (p === 22) {
          return Promise.resolve({
            data: {
              port: 22,
              status: "active",
              is_active: true,
              service_name: "sshd",
              pid: 1042,
              protocol: "TCP",
              can_bind: false,
              is_privileged: true,
              message: "Port 22 sistemde aktif olarak dinleniyor (sshd - PID: 1042). Çakışmayı önlemek için honeypot kurulamaz.",
            },
          });
        }
        return Promise.resolve({
          data: {
            port: p,
            status: "available",
            is_active: false,
            service_name: null,
            pid: null,
            protocol: null,
            can_bind: true,
            is_privileged: p < 1024,
            message: `Port ${p} deaktif (boşta) — honeypot için kullanılabilir.`,
          },
        });
      }
      return Promise.resolve({ data: {} });
    });
  });

  test("başlangıçta aktif tuzakları ve servis butonlarını render etmeli", async () => {
    render(<HoneypotView />);

    expect(screen.getByText(/HoneyPot -- Tuzak Port/i)).toBeInTheDocument();
    expect(screen.getByText("FTP")).toBeInTheDocument();
    expect(screen.getByText("Telnet")).toBeInTheDocument();
    expect(screen.getByText("SSH")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("FTP Tuzağı")).toBeInTheDocument();
      expect(screen.getAllByText(":21").length).toBeGreaterThanOrEqual(1);
    });
  });

  test("dolu 1024 altı port (SSH 22) butonu engelliyor", async () => {
    render(<HoneypotView />);

    const sshBtn = screen.getByRole("button", { name: /SSH :22/i });
    fireEvent.click(sshBtn);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith("/honeypot/check-port/22");
    });

    await waitFor(() => {
      expect(screen.getByText(/Aktif \(Kullanımda: sshd\)/i)).toBeInTheDocument();
      expect(screen.getByText("PID: 1042")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Port Kullanımda \(Aktif Servis\)/i })).toBeDisabled();
    });
  });

  test("boşta 1024 altı port (Telnet 23) tuzak başlatabiliyor", async () => {
    api.post.mockResolvedValueOnce({
      data: {
        success: true,
        message: "Port 23 (TELNET) honeypot olarak aktif edildi. Port deaktif/boşta doğrulandı.",
        port: 23,
        service: "telnet",
      },
    });

    render(<HoneypotView />);

    const telnetBtn = screen.getByRole("button", { name: /Telnet :23/i });
    fireEvent.click(telnetBtn);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith("/honeypot/check-port/23");
    });

    await waitFor(() => {
      expect(screen.getByText(/Deaktif \(Boşta \/ Kullanılabilir\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Ayrıcalıklı/i)).toBeInTheDocument();
    });

    const submitBtn = screen.getByRole("button", { name: /Tuzağı Aktif Et/i });
    expect(submitBtn).not.toBeDisabled();
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith("/honeypot/start", {
        port: 23,
        service: "telnet",
        label: "",
      });
      expect(
        screen.getByText(/Port 23 \(TELNET\) honeypot olarak aktif edildi/i)
      ).toBeInTheDocument();
    });
  });

  test("aktif bir tuzak durdurulduğunda delete api çağrılmalı", async () => {
    api.delete.mockResolvedValueOnce({
      data: { success: true, message: "Port 21 honeypot'u durduruldu." },
    });

    render(<HoneypotView />);

    await waitFor(() => {
      expect(screen.getByText("FTP Tuzağı")).toBeInTheDocument();
    });

    const potItem = screen.getByText("FTP Tuzağı").closest(".pot-item");
    const stopBtn = potItem.querySelector("button");
    fireEvent.click(stopBtn);

    await waitFor(() => {
      expect(api.delete).toHaveBeenCalledWith("/honeypot/stop/21");
      expect(screen.getByText("Port 21 honeypot'u durduruldu.")).toBeInTheDocument();
    });
  });
});

describe("HoneypotView aktif engeller", () => {
  const block = { id: 3, ip: "203.0.113.7", reason: "Telegram onayı", source: "telegram", expires_at: "2026-11-15 10:00:00" };

  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/honeypot/active") return Promise.resolve({ data: { pots: [] } });
      if (url === "/honeypot/blocks") return Promise.resolve({ data: { blocks: [block] } });
      if (url.startsWith("/honeypot/hits")) return Promise.resolve({ data: { hits: [] } });
      return Promise.resolve({ data: {} });
    });
  });

  afterEach(() => jest.restoreAllMocks());

  test("engel listelenir ve kaldırılır", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(true);
    api.delete.mockResolvedValue({ data: { success: true, message: "Engel kaldırıldı." } });
    render(<HoneypotView />);
    expect(await screen.findByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("Aktif Engeller (1)")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Engeli Kaldır"));
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith("/honeypot/blocks/3"));
    await waitFor(() => expect(screen.queryByText("203.0.113.7")).not.toBeInTheDocument());
  });

  test("onay verilmezse kaldırılmaz", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(false);
    render(<HoneypotView />);
    fireEvent.click(await screen.findByText("Engeli Kaldır"));
    expect(api.delete).not.toHaveBeenCalled();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
  });

  test("kaldırma hatası gösterilir", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(true);
    api.delete.mockRejectedValue({ response: { data: { detail: "Başka bir sistem değişikliği sürüyor, bitince tekrar deneyin." } } });
    render(<HoneypotView />);
    fireEvent.click(await screen.findByText("Engeli Kaldır"));
    expect(await screen.findByText(/Başka bir sistem değişikliği sürüyor/)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
  });

  test("yetki yoksa liste görünmez", async () => {
    api.get.mockImplementation((url) => {
      if (url === "/honeypot/blocks") return Promise.reject({ response: { status: 403 } });
      if (url === "/honeypot/active") return Promise.resolve({ data: { pots: [] } });
      return Promise.resolve({ data: { hits: [] } });
    });
    render(<HoneypotView />);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/honeypot/blocks"));
    expect(screen.queryByText(/Aktif Engeller/)).not.toBeInTheDocument();
  });
});
