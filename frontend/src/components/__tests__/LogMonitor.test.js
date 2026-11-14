import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import LogMonitor from "../LogMonitor";
import { api } from "../../api";

jest.mock("../../api", () => ({
  api: { get: jest.fn(), post: jest.fn() },
}));

let sources;

beforeEach(() => {
  sources = [];
  Element.prototype.scrollIntoView = jest.fn();
  global.EventSource = jest.fn((url) => {
    const es = { url, close: jest.fn() };
    sources.push(es);
    return es;
  });
  api.get.mockImplementation((url) => {
    if (url === "/logs/active") return Promise.resolve({ data: { path: "/var/log/auth.log", type: "file", available: true } });
    return Promise.resolve({ data: { logs: [] } });
  });
  api.post.mockResolvedValue({ data: { ticket: "bilet-123", expires_in: 60 } });
});

test("canlı akış önce bilet alıyor, token'ı URL'e koymuyor", async () => {
  localStorage.setItem("puyad_token", "gizli-oturum-token");
  render(<LogMonitor />);
  fireEvent.click(await screen.findByText(/Canlı Başlat/));

  await waitFor(() => expect(sources).toHaveLength(1));
  expect(api.post).toHaveBeenCalledWith("/logs/stream-ticket");
  expect(sources[0].url).toContain("ticket=bilet-123");
  expect(sources[0].url).not.toContain("gizli-oturum-token");
});

test("her yeniden bağlanmada yeni bilet alınıyor", async () => {
  render(<LogMonitor />);
  fireEvent.click(await screen.findByText(/Canlı Başlat/));
  await waitFor(() => expect(sources).toHaveLength(1));

  jest.useFakeTimers();
  api.post.mockResolvedValue({ data: { ticket: "bilet-456", expires_in: 60 } });
  sources[0].onerror();
  jest.advanceTimersByTime(1500);
  jest.useRealTimers();

  await waitFor(() => expect(sources).toHaveLength(2));
  expect(api.post).toHaveBeenCalledTimes(2);
  expect(sources[1].url).toContain("ticket=bilet-456");
});
