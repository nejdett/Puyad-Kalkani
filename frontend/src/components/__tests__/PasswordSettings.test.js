import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import PasswordSettings from "../PasswordSettings";
import { api } from "../../api";

jest.mock("../../api", () => ({ api: { post: jest.fn() } }));

function fill(oldPw, newPw, confirmPw) {
  fireEvent.change(screen.getByLabelText("Mevcut parola"), { target: { value: oldPw } });
  fireEvent.change(screen.getByLabelText("Yeni parola"), { target: { value: newPw } });
  fireEvent.change(screen.getByLabelText("Yeni parola (tekrar)"), { target: { value: confirmPw } });
}

describe("PasswordSettings", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.setItem("puyad_user", "admin");
  });

  test("eşleşmeyen parolada kaydet pasif", () => {
    render(<PasswordSettings onLogout={jest.fn()} />);
    fill("eski-parola-1", "yeni-parola-1", "yeni-parola-2");
    expect(screen.getByText("Parolalar eşleşmiyor.")).toBeInTheDocument();
    expect(screen.getByText("Parolayı Kaydet")).toBeDisabled();
  });

  test("kısa parola uyarısı", () => {
    render(<PasswordSettings onLogout={jest.fn()} />);
    fill("eski-parola-1", "kisa", "kisa");
    expect(screen.getByText("En az 8 karakter olmalı.")).toBeInTheDocument();
    expect(screen.getByText("Parolayı Kaydet")).toBeDisabled();
  });

  test("başarılı değişiklikte API çağrılır", async () => {
    api.post.mockResolvedValueOnce({ data: { success: true } });
    render(<PasswordSettings onLogout={jest.fn()} />);
    fill("eski-parola-1", "yeni-parola-1", "yeni-parola-1");
    fireEvent.click(screen.getByText("Parolayı Kaydet"));
    await waitFor(() => expect(screen.getByText(/Parola değiştirildi/)).toBeInTheDocument());
    expect(api.post).toHaveBeenCalledWith("/auth/change-password", {
      username: "admin", old_password: "eski-parola-1", new_password: "yeni-parola-1",
    });
  });

  test("hatalı mevcut parolada sunucu mesajı gösterilir", async () => {
    api.post.mockRejectedValueOnce({ response: { data: { detail: "Mevcut şifre hatalı." } } });
    render(<PasswordSettings onLogout={jest.fn()} />);
    fill("yanlis-parola", "yeni-parola-1", "yeni-parola-1");
    fireEvent.click(screen.getByText("Parolayı Kaydet"));
    await waitFor(() => expect(screen.getByText("Mevcut şifre hatalı.")).toBeInTheDocument());
  });
});
