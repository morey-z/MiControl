import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, shallowMount } from "@vue/test-utils";
import App from "./App.vue";

vi.mock("./lib/bridge", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./lib/bridge")>();
  return {
    ...actual,
    getRuntimeSnapshot: vi.fn(),
  };
});

import { getRuntimeSnapshot, type RuntimeSnapshot } from "./lib/bridge";

describe("application lifecycle", () => {
  beforeEach(() => {
    vi.mocked(getRuntimeSnapshot).mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("does not create the runtime polling timer after unmount during the initial request", async () => {
    let resolveSnapshot!: (value: RuntimeSnapshot) => void;
    vi.mocked(getRuntimeSnapshot).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveSnapshot = resolve;
      }) as ReturnType<typeof getRuntimeSnapshot>,
    );
    const setIntervalSpy = vi.spyOn(window, "setInterval");
    const wrapper = shallowMount(App, {
      global: {
        stubs: {
          BottomNav: true,
          ButtonsPage: true,
          SettingsPage: true,
        },
      },
    });

    await flushPromises();
    wrapper.unmount();
    resolveSnapshot({} as RuntimeSnapshot);
    await flushPromises();

    expect(setIntervalSpy).not.toHaveBeenCalled();
    setIntervalSpy.mockRestore();
  });

  it("continues polling after a runtime snapshot rejection", async () => {
    vi.useFakeTimers();
    vi.mocked(getRuntimeSnapshot)
      .mockRejectedValueOnce(new Error("runtime unavailable"))
      .mockResolvedValueOnce({} as RuntimeSnapshot);
    const wrapper = shallowMount(App, {
      global: {
        stubs: {
          BottomNav: true,
          ButtonsPage: true,
          SettingsPage: true,
        },
      },
    });

    await flushPromises();
    expect(getRuntimeSnapshot).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(getRuntimeSnapshot).toHaveBeenCalledTimes(2);
    wrapper.unmount();
  });

  it("does not overlap runtime snapshot requests while one is pending", async () => {
    vi.useFakeTimers();
    let resolveSnapshot!: (value: RuntimeSnapshot) => void;
    vi.mocked(getRuntimeSnapshot)
      .mockResolvedValueOnce({} as RuntimeSnapshot)
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveSnapshot = resolve;
        }),
      );
    const wrapper = shallowMount(App, {
      global: {
        stubs: {
          BottomNav: true,
          ButtonsPage: true,
          SettingsPage: true,
        },
      },
    });

    await flushPromises();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(getRuntimeSnapshot).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(getRuntimeSnapshot).toHaveBeenCalledTimes(2);
    resolveSnapshot({} as RuntimeSnapshot);
    await flushPromises();
    wrapper.unmount();
  });
});
