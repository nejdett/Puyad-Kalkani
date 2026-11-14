import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import RuleManager from "../RuleManager";
import { getRules, addRule, updateRule, deleteRule } from "../../api";

jest.mock("../../api", () => ({
  getRules: jest.fn(),
  addRule: jest.fn(),
  updateRule: jest.fn(),
  deleteRule: jest.fn(),
}));

describe("RuleManager Bileşeni", () => {
  const sampleRules = [
    {
      id: "rule_ssh_root",
      name: "SSH Root Login Kapat",
      category: "SSH",
      severity: "high",
      check_command: "grep -q 'PermitRootLogin no' /etc/ssh/sshd_config && echo OK || echo FAIL",
      fix_command: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      description: "SSH üzerinden root girişini engeller.",
    },
    {
      id: "rule_password_max_days",
      name: "Parola Geçerlilik Süresi",
      category: "Sistem",
      severity: "medium",
      check_command: "grep -q '^PASS_MAX_DAYS 90' /etc/login.defs && echo OK || echo FAIL",
      fix_command: "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
      description: "Parolaların 90 günde bir değiştirilmesini sağlar.",
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    window.scrollTo = jest.fn();
    window.HTMLElement.prototype.scrollIntoView = jest.fn();
    getRules.mockResolvedValue({ data: { rules: sampleRules } });
  });

  test("kuralları listelemeli ve sayfa başlığını göstermeli", async () => {
    render(<RuleManager />);

    expect(screen.getByText("Kural Yönetimi")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("SSH Root Login Kapat")).toBeInTheDocument();
      expect(screen.getByText("Parola Geçerlilik Süresi")).toBeInTheDocument();
    });
  });

  test("Düzenle formu kural verisiyle açıyor", async () => {
    render(<RuleManager />);

    await waitFor(() => {
      expect(screen.getByText("SSH Root Login Kapat")).toBeInTheDocument();
    });

    const editButtons = screen.getAllByRole("button", { name: /Düzenle/i });
    fireEvent.click(editButtons[0]);

    expect(screen.getByText("Kuralı Düzenle")).toBeInTheDocument();
    expect(screen.getByDisplayValue("SSH Root Login Kapat")).toBeInTheDocument();
    expect(screen.getByDisplayValue("rule_ssh_root")).toBeInTheDocument();

    expect(window.scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });
  });

  test("Yeni Kural butonuna basıldığında formu açmalı", async () => {
    render(<RuleManager />);

    await waitFor(() => {
      expect(screen.getByText("SSH Root Login Kapat")).toBeInTheDocument();
    });

    const newRuleBtn = screen.getByRole("button", { name: /Yeni Kural/i });
    fireEvent.click(newRuleBtn);

    expect(screen.getByText("Yeni Kural Tanımla")).toBeInTheDocument();
    expect(window.scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });
  });

  test("Düzenleme formunda güncelleme yapabilmeli", async () => {
    updateRule.mockResolvedValueOnce({ data: { success: true } });

    render(<RuleManager />);

    await waitFor(() => {
      expect(screen.getByText("SSH Root Login Kapat")).toBeInTheDocument();
    });

    const editButtons = screen.getAllByRole("button", { name: /Düzenle/i });
    fireEvent.click(editButtons[0]);

    const nameInput = screen.getByDisplayValue("SSH Root Login Kapat");
    fireEvent.change(nameInput, { target: { name: "name", value: "SSH Root Login Devre Dışı" } });

    const submitBtn = screen.getByRole("button", { name: "Güncelle" });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(updateRule).toHaveBeenCalledWith("rule_ssh_root", expect.objectContaining({
        name: "SSH Root Login Devre Dışı",
      }));
    });
  });

  test("tehlikeli shell komutu girildiğinde form hata göstermeli ve kaydetmeyi engellemeli", async () => {
    const { container } = render(<RuleManager />);

    await waitFor(() => {
      expect(screen.getByText("SSH Root Login Kapat")).toBeInTheDocument();
    });

    const newRuleBtn = screen.getByRole("button", { name: /Yeni Kural/i });
    fireEvent.click(newRuleBtn);

    const checkInput = container.querySelector('textarea[name="check_command"]');
    fireEvent.change(checkInput, {
      target: { name: "check_command", value: 'awk \'BEGIN {system("nc 127.0.0.1 9001 -e /bin/bash")}\'' },
    });
    fireEvent.blur(checkInput);

    expect(screen.getByText(/güvenli değil: Tehlikeli komut veya shell çalıştırma deseni tespit edildi/i)).toBeInTheDocument();
    const saveBtn = screen.getByRole("button", { name: "Kaydet" });
    expect(saveBtn).toBeDisabled();
  });
});
