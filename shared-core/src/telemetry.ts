/**
 * telemetry.ts - OpenTelemetry SDK 初始化
 *
 * 依赖环境：Vite + ESM（Tauri Desktop / Capacitor Mobile）
 */
import 'zone.js';

import { WebTracerProvider } from '@opentelemetry/sdk-trace-web';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { ZoneContextManager } from '@opentelemetry/context-zone';
import {
  CompositePropagator,
  W3CTraceContextPropagator,
  W3CBaggagePropagator,
} from '@opentelemetry/core';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { FetchInstrumentation } from '@opentelemetry/instrumentation-fetch';
import { XMLHttpRequestInstrumentation } from '@opentelemetry/instrumentation-xml-http-request';
import { DocumentLoadInstrumentation } from '@opentelemetry/instrumentation-document-load';
import {
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
  AlwaysOnSampler,
} from '@opentelemetry/sdk-trace-base';
import { trace, context, Tracer } from '@opentelemetry/api';

const DEFAULT_OTLP_ENDPOINT = 'http://localhost:4318/v1/traces';

function getOtlpEndpoint(): string {
  try {
    const env = (import.meta as { env?: Record<string, string> })?.env;
    return env?.VITE_OTEL_ENDPOINT || DEFAULT_OTLP_ENDPOINT;
  } catch {
    return DEFAULT_OTLP_ENDPOINT;
  }
}

function isDevMode(): boolean {
  try {
    const env = (import.meta as { env?: Record<string, string> })?.env;
    return env?.VITE_DEBUG === 'true';
  } catch {
    return false;
  }
}

let telemetryEnabled = true;

export function setTelemetryEnabled(enabled: boolean): void {
  telemetryEnabled = enabled;
}

export function isTelemetryEnabled(): boolean {
  return telemetryEnabled;
}

let provider: WebTracerProvider | null = null;
let isInitialized = false;

export function initTelemetry(deviceTag: string): void {
  if (isInitialized) return;

  // 没有 collector 端点时跳过初始化，避免连接 localhost:4318 失败
  // 设置 VITE_OTEL_ENDPOINT 环境变量即可启用（如 http://localhost:4318/v1/traces）
  const endpoint = getOtlpEndpoint();
  if (!endpoint || endpoint === DEFAULT_OTLP_ENDPOINT) {
    isInitialized = true;
    telemetryEnabled = false;
    return;
  }

  isInitialized = true;

  const resource = new Resource({
    [ATTR_SERVICE_NAME]: 'lan-backup-tool',
    [ATTR_SERVICE_VERSION]: '1.0.0',
    'device.type': deviceTag,
    'deployment.environment': isDevMode() ? 'development' : 'production',
  });

  const otlpExporter = new OTLPTraceExporter({
    url: getOtlpEndpoint(),
  });

  const spanProcessor = new BatchSpanProcessor(otlpExporter, {
    maxQueueSize: 2048,
    maxExportBatchSize: 512,
    scheduledDelayMillis: 2000,
    exportTimeoutMillis: 30000,
  });

  const sampler = new ParentBasedSampler({
    root: isDevMode()
      ? new AlwaysOnSampler()
      : new TraceIdRatioBasedSampler(0.1),
  });

  provider = new WebTracerProvider({
    resource,
    sampler,
    spanProcessors: [spanProcessor],
  });

  provider.register({
    contextManager: new ZoneContextManager(),
    propagator: new CompositePropagator({
      propagators: [
        new W3CTraceContextPropagator(),
        new W3CBaggagePropagator(),
      ],
    }),
  });

  registerInstrumentations({
    tracerProvider: provider,
    instrumentations: [
      new FetchInstrumentation({
        propagateTraceHeaderCorsUrls: [
          /^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/,
        ],
      }),
      new XMLHttpRequestInstrumentation({
        propagateTraceHeaderCorsUrls: [
          /^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/,
        ],
      }),
      new DocumentLoadInstrumentation(),
    ],
  });
}

function createNoopTracer(): Tracer {
  const noopSpan = {
    setAttribute: () => {},
    setAttributes: () => {},
    setStatus: () => {},
    recordException: () => {},
    end: () => {},
    spanContext: () => ({ traceId: '', spanId: '', traceFlags: 0, isRemote: false }),
    isRecording: () => false,
    addEvent: () => {},
  };

  return new Proxy({} as Tracer, {
    get: (_target, prop) => {
      if (prop === 'startActiveSpan') {
        return (name: string, optsOrFn: unknown, ctx?: unknown, fn?: unknown) => {
          const cb = typeof optsOrFn === 'function' ? optsOrFn : fn;
          return cb ? (cb as (span: typeof noopSpan) => unknown)(noopSpan) : noopSpan;
        };
      }
      if (prop === 'startSpan') {
        return (_name: string, _opts?: unknown, _ctx?: unknown) => noopSpan;
      }
      if (prop === 'spanBuilder') {
        return (_name: string) => ({
          setAttribute: () => {},
          setAttributes: () => {},
          setStatus: () => {},
          startSpan: () => noopSpan,
          start: () => noopSpan,
          setParent: () => {},
          setNoParent: () => {},
          addEvent: () => {},
          recordException: () => {},
        });
      }
      return () => noopSpan;
    },
  });
}

export function getTracer(): Tracer {
  if (!isTelemetryEnabled() || !provider) {
    return createNoopTracer();
  }
  return provider.getTracer('lan-backup-tool', '1.0.0');
}

export function currentTraceId(): string | undefined {
  if (!isTelemetryEnabled()) return undefined;
  const span = trace.getSpan(context.active());
  return span?.spanContext().traceId;
}

export async function shutdownTelemetry(): Promise<void> {
  if (provider) {
    await provider.shutdown();
    provider = null;
    isInitialized = false;
  }
}
