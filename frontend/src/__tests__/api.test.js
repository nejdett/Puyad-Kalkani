import { api, scanSystem, scanSingleRule, fixRule, ignoreRule, unignoreRule, getIgnored, getRules, addRule, updateRule, deleteRule } from "../api";

describe("API Modülü", () => {
  test("api objesi tanımlı olmalı", () => {
    expect(api).toBeDefined();
  });

  test("api baseURL doğru olmalı", () => {
    expect(api.defaults.baseURL).toBe("/api");
  });

  test("api timeout doğru olmalı", () => {
    expect(api.defaults.timeout).toBe(15000);
  });

  test("scanSystem fonksiyonu tanımlı olmalı", () => {
    expect(typeof scanSystem).toBe("function");
  });

  test("scanSingleRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof scanSingleRule).toBe("function");
  });

  test("fixRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof fixRule).toBe("function");
  });

  test("ignoreRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof ignoreRule).toBe("function");
  });

  test("unignoreRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof unignoreRule).toBe("function");
  });

  test("getIgnored fonksiyonu tanımlı olmalı", () => {
    expect(typeof getIgnored).toBe("function");
  });

  test("getRules fonksiyonu tanımlı olmalı", () => {
    expect(typeof getRules).toBe("function");
  });

  test("addRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof addRule).toBe("function");
  });

  test("updateRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof updateRule).toBe("function");
  });

  test("deleteRule fonksiyonu tanımlı olmalı", () => {
    expect(typeof deleteRule).toBe("function");
  });

  test("scanSystem GET isteği yapmalı", () => {
    const spy = jest.spyOn(api, "get").mockResolvedValue({ data: {} });
    scanSystem();
    expect(spy).toHaveBeenCalledWith("/scan", { timeout: 120000 });
    spy.mockRestore();
  });

  test("scanSingleRule doğru URL ile GET isteği yapmalı", () => {
    const spy = jest.spyOn(api, "get").mockResolvedValue({ data: {} });
    scanSingleRule("test-rule");
    expect(spy).toHaveBeenCalledWith("/scan/test-rule", { timeout: 30000 });
    spy.mockRestore();
  });

  test("fixRule doğru URL ile POST isteği yapmalı", () => {
    const spy = jest.spyOn(api, "post").mockResolvedValue({ data: {} });
    fixRule("test-rule");
    expect(spy).toHaveBeenCalledWith("/fix/test-rule", {}, { timeout: 120000 });
    spy.mockRestore();
  });

  test("ignoreRule doğru URL ile POST isteği yapmalı", () => {
    const spy = jest.spyOn(api, "post").mockResolvedValue({ data: {} });
    ignoreRule("test-rule");
    expect(spy).toHaveBeenCalledWith("/ignore/test-rule");
    spy.mockRestore();
  });

  test("unignoreRule doğru URL ile DELETE isteği yapmalı", () => {
    const spy = jest.spyOn(api, "delete").mockResolvedValue({ data: {} });
    unignoreRule("test-rule");
    expect(spy).toHaveBeenCalledWith("/ignore/test-rule");
    spy.mockRestore();
  });

  test("getIgnored doğru URL ile GET isteği yapmalı", () => {
    const spy = jest.spyOn(api, "get").mockResolvedValue({ data: {} });
    getIgnored();
    expect(spy).toHaveBeenCalledWith("/ignored");
    spy.mockRestore();
  });

  test("getRules doğru URL ile GET isteği yapmalı", () => {
    const spy = jest.spyOn(api, "get").mockResolvedValue({ data: {} });
    getRules();
    expect(spy).toHaveBeenCalledWith("/rules");
    spy.mockRestore();
  });

  test("addRule doğru URL ile POST isteği yapmalı", () => {
    const spy = jest.spyOn(api, "post").mockResolvedValue({ data: {} });
    const rule = { id: "test", name: "Test" };
    addRule(rule);
    expect(spy).toHaveBeenCalledWith("/rules", rule);
    spy.mockRestore();
  });

  test("updateRule doğru URL ile PUT isteği yapmalı", () => {
    const spy = jest.spyOn(api, "put").mockResolvedValue({ data: {} });
    const rule = { name: "Updated" };
    updateRule("test-rule", rule);
    expect(spy).toHaveBeenCalledWith("/rules/test-rule", rule);
    spy.mockRestore();
  });

  test("deleteRule doğru URL ile DELETE isteği yapmalı", () => {
    const spy = jest.spyOn(api, "delete").mockResolvedValue({ data: {} });
    deleteRule("test-rule");
    expect(spy).toHaveBeenCalledWith("/rules/test-rule");
    spy.mockRestore();
  });

  test("401 interceptor session state'i silmemeli (App.js /auth/me kontrolü yapar)", async () => {
    localStorage.setItem("puyad_token", "stale-token");
    localStorage.setItem("puyad_user", "admin");

    api.defaults.adapter = (config) => {
      return Promise.reject({
        config,
        response: { status: 401, data: { detail: "Token expired" } },
      });
    };

    try {
      await api.get("/admin/rate-limit/config");
    } catch (e) {
    }

    expect(localStorage.getItem("puyad_token")).toBe("stale-token");
    expect(localStorage.getItem("puyad_user")).toBe("admin");
  });
});
