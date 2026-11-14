import React from "react";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import "@testing-library/jest-dom";
import ServerManagement from "../ServerManagement";
import { api } from "../../api";

jest.mock("../../api", () => ({
  api: {
    get: jest.fn(),
    post: jest.fn(),
    patch: jest.fn(),
    delete: jest.fn(),
  },
}));

describe("ServerManagement anahtar üretimi", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/servers") return Promise.resolve({ data: { servers: [] } });
      if (url === "/servers/probe-all") return Promise.resolve({ data: { results: [] } });
      return Promise.resolve({ data: {} });
    });
  });

  test("crypto ile 32 karakterlik hex anahtar üretir", async () => {
    const original = window.crypto;
    const getRandomValues = jest.fn((arr) => arr.fill(171));
    Object.defineProperty(window, "crypto", { value: { getRandomValues }, configurable: true });
    try {
      render(<ServerManagement />);
      await waitFor(() => expect(api.get).toHaveBeenCalledWith("/config/agent-secret"));
      fireEvent.click(await screen.findByTitle("Yeni rastgele anahtar üret"));
      const input = screen.getByPlaceholderText("Ajan güvenlik anahtarı (secret / token)");
      await waitFor(() => expect(input.value).toBe("5".repeat(32)));
      expect(getRandomValues).toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "crypto", { value: original, configurable: true });
    }
  });

  test("crypto yoksa anahtar üretmez ve hata gösterir", async () => {
    const original = window.crypto;
    Object.defineProperty(window, "crypto", { value: undefined, configurable: true });
    const randomSpy = jest.spyOn(Math, "random");
    try {
      render(<ServerManagement />);
      fireEvent.click(await screen.findByTitle("Yeni rastgele anahtar üret"));
      await waitFor(() => expect(screen.getByText(/anahtar üretilemedi/)).toBeInTheDocument());
      expect(screen.getByPlaceholderText("Ajan güvenlik anahtarı (secret / token)").value).toBe("");
      expect(randomSpy).not.toHaveBeenCalled();
    } finally {
      randomSpy.mockRestore();
      Object.defineProperty(window, "crypto", { value: original, configurable: true });
    }
  });
});

describe("ServerManagement sunucu token'ı düzenleme", () => {
  const server = { id: 2, name: "web-1", ip_address: "192.168.1.20", port: 8000, status: "online", last_score: 80, token: "********abcd" };

  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/servers") return Promise.resolve({ data: { servers: [server] } });
      if (url === "/servers/probe-all") return Promise.resolve({ data: { results: [] } });
      return Promise.resolve({ data: {} });
    });
    api.patch.mockResolvedValue({ data: { success: true } });
  });

  async function openEditor() {
    render(<ServerManagement />);
    fireEvent.click(await screen.findByTitle("Sunucu token'ını düzenle"));
  }

  test("boş bırakılıp kaydedilince istek atmaz, token korunur", async () => {
    await openEditor();
    fireEvent.click(screen.getByTitle("Token'ı kaydet"));
    await waitFor(() => expect(screen.getByText("Token değiştirilmedi.")).toBeInTheDocument());
    expect(api.patch).not.toHaveBeenCalled();
    expect(screen.getByText("Özel Token")).toBeInTheDocument();
  });

  test("yeni token girilince yalnızca token gönderilir", async () => {
    await openEditor();
    fireEvent.change(screen.getByPlaceholderText(/boş bırakılırsa değişmez/), { target: { value: " yeni-token-1234 " } });
    fireEvent.click(screen.getByTitle("Token'ı kaydet"));
    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/servers/2", { token: "yeni-token-1234" }));
  });

  test("Token'ı kaldır seçilince clear_token gönderilir", async () => {
    await openEditor();
    fireEvent.click(screen.getByLabelText("Token'ı kaldır"));
    expect(screen.getByPlaceholderText(/boş bırakılırsa değişmez/)).toBeDisabled();
    fireEvent.click(screen.getByTitle("Token'ı kaydet"));
    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/servers/2", { clear_token: true }));
    await waitFor(() => expect(screen.getByText("Genel Anahtar")).toBeInTheDocument());
  });
});

describe("ServerManagement ajan TLS sertifikası", () => {
  const fp = "ab".repeat(32);
  const pending = { id: 3, name: "db-1", ip_address: "192.168.1.30", port: 8000, status: "online", last_score: 70, token: "", agent_cert_status: "pending", agent_cert_fingerprint: fp };

  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/servers") return Promise.resolve({ data: { servers: [pending] } });
      if (url === "/servers/probe-all") return Promise.resolve({ data: { results: [] } });
      if (url === "/config") return Promise.resolve({ data: { RUN_MODE: "controller" } });
      if (url === "/agent/install-command") {
        return Promise.resolve({ data: { command: "curl -sSf -k --pinnedpubkey 'sha256//X' https://10.0.0.1:8000/api/agent/update.sh -o update.sh && bash update.sh", fingerprint: "cd".repeat(32) } });
      }
      return Promise.resolve({ data: {} });
    });
    api.post.mockResolvedValue({ data: { success: true } });
    api.delete.mockResolvedValue({ data: { success: true } });
  });

  afterEach(() => {
    window.confirm.mockRestore?.();
  });

  test("onay bekleyen sertifikayı parmak iziyle onaylar", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(true);
    render(<ServerManagement />);
    expect(await screen.findByText(fp)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Onayla"));
    await waitFor(() => expect(api.post).toHaveBeenCalledWith("/servers/3/cert/approve", { fingerprint: fp }));
    expect(window.confirm.mock.calls[0][0]).toContain(fp);
    expect(await screen.findByText("Onaylı")).toBeInTheDocument();
  });

  test("onay iptal edilince istek atmaz", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(false);
    render(<ServerManagement />);
    fireEvent.click(await screen.findByText("Onayla"));
    expect(api.post).not.toHaveBeenCalled();
    expect(screen.getByText("Onay bekliyor")).toBeInTheDocument();
  });

  test("sıfırlama sertifikayı kaldırır", async () => {
    jest.spyOn(window, "confirm").mockReturnValue(true);
    render(<ServerManagement />);
    fireEvent.click(await screen.findByTitle("Ajan sertifikasını sıfırla"));
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith("/servers/3/cert"));
    expect(await screen.findByText("Sertifika yok")).toBeInTheDocument();
    expect(screen.queryByText(fp)).not.toBeInTheDocument();
  });

  test("kurulum komutunu girilen adresle ister ve gösterir", async () => {
    render(<ServerManagement />);
    const input = await screen.findByPlaceholderText("Controller adresi (örn: 192.168.1.10:8000)");
    fireEvent.change(input, { target: { value: "10.0.0.1:8000" } });
    fireEvent.click(screen.getByText("Komutu Oluştur"));
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/agent/install-command", { params: { host: "10.0.0.1:8000" } }));
    expect(await screen.findByText(/--pinnedpubkey 'sha256\/\/X'/)).toBeInTheDocument();
    expect(screen.getByText("cd".repeat(32))).toBeInTheDocument();
  });
});

describe("ServerManagement tarama işi", () => {
  const server = { id: 2, name: "web-1", ip_address: "192.168.1.20", port: 8000, status: "online", last_score: 40 };

  function mockJobs(current, polls) {
    api.get.mockImplementation((url) => {
      if (url === "/servers") return Promise.resolve({ data: { servers: [server] } });
      if (url === "/servers/probe-all") return Promise.resolve({ data: { results: [] } });
      if (url === "/jobs/current") return Promise.resolve({ data: { job: current } });
      if (url.startsWith("/jobs/")) return Promise.resolve({ data: { job: polls.length > 1 ? polls.shift() : polls[0] } });
      return Promise.resolve({ data: {} });
    });
  }

  beforeEach(() => jest.clearAllMocks());
  afterEach(() => jest.useRealTimers());

  test("süren uzak tarama geri dönünce görünür", async () => {
    jest.useFakeTimers();
    const job = { id: 4, server_id: 2, status: "running" };
    mockJobs(job, [job, { ...job, status: "done", result: { summary: { score: 90, total: 1 }, results: [] } }]);
    render(<ServerManagement />);
    expect(await screen.findByText("Taranıyor...")).toBeInTheDocument();
    await act(async () => { jest.advanceTimersByTime(3000); });
    expect(await screen.findByText(/Tarama tamamlandı: web-1/)).toBeInTheDocument();
    expect(screen.queryByText("Taranıyor...")).not.toBeInTheDocument();
  });

  test("biten iş için tarama gösterilmez", async () => {
    mockJobs({ id: 4, server_id: 2, status: "done", result: {} }, []);
    render(<ServerManagement />);
    await screen.findByText("web-1");
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/jobs/current", { params: { kind: "scan" } }));
    expect(screen.queryByText("Taranıyor...")).not.toBeInTheDocument();
    expect(api.get).not.toHaveBeenCalledWith("/jobs/4");
  });
});
