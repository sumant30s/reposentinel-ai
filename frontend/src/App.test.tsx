import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { api, setToken } from "./api";
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  setToken("");
});
function show() {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
          },
        })
      }
    >
      <App />
    </QueryClientProvider>,
  );
}
describe("workspace access and API", () => {
  it("requires a token and describes its storage", () => {
    show();
    expect(screen.getByLabelText("Workspace token")).toHaveAttribute(
      "type",
      "password",
    );
    expect(screen.getByText(/token stays in memory/)).toBeInTheDocument();
  });
  it("shows authentication failures instead of dashboard data", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue({
          ok: false,
          status: 401,
          json: async () => ({ detail: "Invalid or missing bearer token" }),
        }),
    );
    show();
    fireEvent.change(screen.getByLabelText("Workspace token"), {
      target: { value: "a".repeat(40) },
    });
    fireEvent.click(screen.getByRole("button", { name: /connect securely/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Invalid or missing bearer token",
    );
  });
  it("opens the empty dashboard after successful authentication", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation(async (url: string) => ({
          ok: true,
          json: async () =>
            url.endsWith("/settings")
              ? {
                  ai_provider: "none",
                  exclusions: [],
                  engines: "",
                  allowed_repos: "",
                }
              : [],
        })),
    );
    show();
    fireEvent.change(screen.getByLabelText("Workspace token"), {
      target: { value: "b".repeat(40) },
    });
    fireEvent.click(screen.getByRole("button", { name: /connect securely/i }));
    expect(
      await screen.findByText("Your security overview"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /scan the demo project/i }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /lock workspace/i }));
    await waitFor(() =>
      expect(screen.getByText("Open your workspace")).toBeInTheDocument(),
    );
  });
  it("uses bearer headers and exposes server errors", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue({
        ok: false,
        status: 429,
        json: async () => ({ detail: "Queue full" }),
      });
    vi.stubGlobal("fetch", fetcher);
    setToken("example-memory-token");
    await expect(api("/scans")).rejects.toThrow("Queue full");
    const options = fetcher.mock.calls[0][1];
    expect(options.headers.get("Authorization")).toBe(
      "Bearer example-memory-token",
    );
  });
});
