import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import LoginPage from "../LoginPage";
import { api } from "../../api";

jest.mock("../../api", () => ({
  api: {
    post: jest.fn(),
  },
}));

describe("LoginPage Bileşeni", () => {
  const mockOnLogin = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
  });

  test("login formu render edilmeli", () => {
    render(<LoginPage onLogin={mockOnLogin} />);

    expect(screen.getByText("Puyad Kalkanı")).toBeInTheDocument();
    expect(screen.getByText("Linux Hardening Platform")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("admin")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("••••••••")).toBeInTheDocument();
    expect(screen.getByText("Giriş Yap")).toBeInTheDocument();
  });

  test("boş formda giriş butonu devre dışı olmalı ve istek atılmamalı", () => {
    render(<LoginPage onLogin={mockOnLogin} />);

    const btn = screen.getByText("Giriş Yap");
    expect(btn).toBeDisabled();
    expect(api.post).not.toHaveBeenCalled();
  });

  test("sadece kullanıcı adı girildiğinde şifre eksikken buton devre dışı olmalı", () => {
    render(<LoginPage onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText("admin"), { target: { value: "admin" } });
    const btn = screen.getByText("Giriş Yap");
    expect(btn).toBeDisabled();
    expect(api.post).not.toHaveBeenCalled();
  });

  test("başarılı login onLogin çağırmalı", async () => {
    api.post.mockResolvedValueOnce({
      data: { access_token: "test-token", username: "admin" },
    });

    render(<LoginPage onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText("admin"), { target: { value: "admin" } });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), { target: { value: "test-parola-123" } });
    fireEvent.click(screen.getByText("Giriş Yap"));

    await waitFor(() => {
      expect(mockOnLogin).toHaveBeenCalledWith("admin");
    });

    expect(localStorage.getItem("puyad_token")).toBe("test-token");
    expect(localStorage.getItem("puyad_user")).toBe("admin");
  });

  test("başarısız login hata mesajı göstermeli", async () => {
    api.post.mockRejectedValueOnce({
      response: { data: { detail: "Kullanıcı adı veya şifre hatalı." } },
    });

    render(<LoginPage onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText("admin"), { target: { value: "admin" } });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByText("Giriş Yap"));

    await waitFor(() => {
      expect(screen.getByText("Kullanıcı adı veya şifre hatalı.")).toBeInTheDocument();
    });

    expect(mockOnLogin).not.toHaveBeenCalled();
  });

  test("loading durumunda buton devre dışı olmalı", async () => {
    api.post.mockImplementation(() => new Promise(() => {}));

    render(<LoginPage onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText("admin"), { target: { value: "admin" } });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), { target: { value: "test-parola-123" } });
    fireEvent.click(screen.getByText("Giriş Yap"));

    await waitFor(() => {
      expect(screen.getByText("Doğrulanıyor...")).toBeInTheDocument();
    });

    expect(screen.getByText("Doğrulanıyor...")).toBeDisabled();
  });

  test("varsayılan giriş ipucu görünmeli", () => {
    render(<LoginPage onLogin={mockOnLogin} />);

    expect(screen.getByText(/Varsayılan:/)).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("puyad2026")).toBeInTheDocument();
  });
});
