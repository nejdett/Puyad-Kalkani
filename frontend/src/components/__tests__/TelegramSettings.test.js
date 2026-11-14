import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import TelegramSettings from "../TelegramSettings";
import { api } from "../../api";

jest.mock("../../api", () => ({
  api: {
    get: jest.fn(),
    post: jest.fn(),
    patch: jest.fn(),
  },
}));

describe("TelegramSettings Bileşeni", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    api.get.mockImplementation((url) => {
      if (url === "/config") {
        return Promise.resolve({
          data: {
            TELEGRAM_ENABLED: true,
            TELEGRAM_BOT_TOKEN: "********TEST",
            TELEGRAM_CHAT_ID: "100000001",
          },
        });
      }
      if (url === "/telegram/pending") {
        return Promise.resolve({ data: { pending: [] } });
      }
      return Promise.resolve({ data: {} });
    });
  });

  test("kayıtlı ve maskelenmiş token ile başlangıç durumu render edilmeli", async () => {
    render(<TelegramSettings />);

    expect(screen.getByText("Telegram Bildirim Ayarları")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/••••••••TEST/)).toBeInTheDocument();
    });
  });

  test("kayıtlı token varken test mesajı gönderildiğinde maskeli token gönderilmemeli", async () => {
    api.post.mockResolvedValueOnce({
      data: { success: true, message: "Test mesajı gönderildi." },
    });

    render(<TelegramSettings />);

    await waitFor(() => {
      expect(screen.getByText(/••••••••TEST/)).toBeInTheDocument();
    });

    const testBtn = screen.getByRole("button", { name: /Test Mesajı Gönder/i });
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith("/telegram/test", {});
      expect(screen.getByText("Test mesajı gönderildi.")).toBeInTheDocument();
    });
  });

  test("test mesajı düzenlenen yeni token ile gidiyor", async () => {
    api.post.mockResolvedValueOnce({
      data: { success: true, message: "Test mesajı gönderildi." },
    });

    render(<TelegramSettings />);

    await waitFor(() => {
      expect(screen.getByText(/••••••••TEST/)).toBeInTheDocument();
    });

    const maskedBox = screen.getByText(/••••••••TEST/);
    fireEvent.click(maskedBox);

    const input = screen.getByPlaceholderText("123456:ABC-DEF...");
    fireEvent.change(input, {
      target: { value: "123456789:ABCDEF12345678901234567890123456" },
    });

    const testBtn = screen.getByRole("button", { name: /Test Mesajı Gönder/i });
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith("/telegram/test", {
        bot_token: "123456789:ABCDEF12345678901234567890123456",
      });
    });
  });

  test("kaydet butonuna basıldığında ayarlar güncellenmeli", async () => {
    api.patch.mockResolvedValueOnce({ data: { success: true } });

    render(<TelegramSettings />);

    await waitFor(() => {
      expect(screen.getByText(/••••••••TEST/)).toBeInTheDocument();
    });

    const saveBtn = screen.getByRole("button", { name: /Kaydet/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(api.patch).toHaveBeenCalledWith("/config", {
        TELEGRAM_ENABLED: true,
      });
    });
  });
});
