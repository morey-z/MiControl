import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ButtonsPage from "./ButtonsPage.vue";
import type { ButtonMappings, RuntimeSnapshot } from "../lib/bridge";

const saveButtonMappings = vi.hoisted(() =>
  vi.fn(async (mappings: ButtonMappings) => mappings),
);

vi.mock("../lib/bridge", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/bridge")>();
  return {
    ...actual,
    getButtonMappings: vi.fn(async () => ({ enabled: true, actions: {} })),
    getButtonMappingSnapshot: vi.fn(async () => ({
      enabled: true,
      gateActive: true,
      listenerActive: true,
      swallowedEdges: 0,
      leakedDowns: 0,
      firedGestures: 0,
      lastFired: null,
      lastError: null,
    })),
    listPresetApps: vi.fn(async () => []),
    saveButtonMappings,
    subscribeButtonEdges: vi.fn(async () => () => undefined),
    subscribeButtonGestures: vi.fn(async () => () => undefined),
    subscribeShortcutCaptureEdges: vi.fn(async () => () => undefined),
    startRawInput: vi.fn(async () => undefined),
    stopRawInput: vi.fn(async () => undefined),
    getHidTapStatus: vi.fn(async () => null),
  };
});

const runtimeFor = (model: "rc001" | "rc003" | "unknown"): RuntimeSnapshot =>
  ({
    appVersion: "0.1.0",
    platform: {
      platform: "windows",
      windowsApiAvailable: true,
      bleScanAvailable: true,
      bleVoiceReady: true,
      wasapiReady: false,
      rawInputReady: true,
      sendInputReady: true,
      verificationStatus: "测试",
      connection: {
        phase: "ready",
        remoteName: "测试遥控器",
        remoteModel: model,
        capabilities: null,
        voiceState: "idle",
        decodedSamples: 0,
        generation: 0,
        reconnectAttempt: 0,
        powerNotificationsAvailable: false,
        lastError: null,
      },
      audio: {
        phase: "unsupported",
        selectedEndpointId: null,
        selectedEndpointName: null,
        queuedSamples: 0,
        submittedSamples: 0,
        generation: 0,
        lastError: null,
      },
      rawInput: {
        phase: "ready",
        matchedDeviceCount: 1,
        rawEventCount: 0,
        semanticEdgeCount: 0,
        lastButton: null,
        lastIsPressed: null,
        activeButtons: [],
        lastError: null,
      },
      buttonMapping: {
        enabled: true,
        gateActive: true,
        listenerActive: true,
        swallowedEdges: 0,
        leakedDowns: 0,
        firedGestures: 0,
        lastFired: null,
        lastError: null,
      },
    },
  }) as RuntimeSnapshot;

beforeEach(() => saveButtonMappings.mockClear());

describe("return and volume mapping independent coverage", () => {
  it("keeps all three trigger cells editable and in the save payload for every model", async () => {
    for (const model of ["rc001", "rc003", "unknown"] as const) {
      saveButtonMappings.mockClear();
      const wrapper = mount(ButtonsPage, { props: { runtime: runtimeFor(model) } });
      await flushPromises();

      for (const button of ["返回", "音量+", "音量−"] as const) {
        const card = wrapper.findAll(".mapping-card").find((item) => item.text().includes(button));
        expect(card, `${model} 缺少 ${button} 卡片`).toBeDefined();
        for (const index of [0, 1, 2]) {
          const cell = card!.findAll(".mapping-cell")[index]!;
          expect((cell.element as HTMLButtonElement).disabled, `${model}/${button}/${index}`).toBe(false);
          await cell.trigger("click");
          await wrapper.find(".mapping-editor .chip").trigger("click");
          await vi.waitFor(() => expect(saveButtonMappings).toHaveBeenCalled());
        }
      }

      const payload = saveButtonMappings.mock.lastCall![0];
      for (const button of ["back", "volume_up", "volume_down"] as const) {
        for (const trigger of ["single", "double", "long"] as const) {
          expect(payload.actions[button]?.[trigger]?.type, `${model}/${button}/${trigger}`).toBe("shortcut");
        }
      }
      expect(wrapper.find(".voice-card").text()).toContain("不参与自定义映射");
      expect(wrapper.find(".voice-card").findAll(".mapping-cell")).toHaveLength(0);
      wrapper.unmount();
    }
  });
});
