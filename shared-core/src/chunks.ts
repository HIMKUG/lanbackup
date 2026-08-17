/**
 * chunks.ts - 主线程时间分片工具
 *
 * 大数组的同步批量处理（如清单构建、锚点合并、状态更新）会阻塞主线程，
 * 导致 UI 卡顿。processInChunks() 借助 requestAnimationFrame 把处理拆成
 * 每帧一批的微任务，让出主线程保证渲染流畅；处理顺序与结果与同步版完全一致。
 */

/** 每帧处理条数上限（默认 100 条/帧，约 1-2ms） */
const DEFAULT_BATCH = 100;

/**
 * 分片处理大数组：每帧最多处理 batchSize 条，处理完所有条目后 resolve。
 * @param items 待处理数组
 * @param fn 逐条处理函数（同步，抛错会中断整个流程）
 * @param batchSize 每帧处理条数
 */
export async function processInChunks<T>(
  items: T[],
  fn: (item: T, index: number) => void,
  batchSize: number = DEFAULT_BATCH,
): Promise<void> {
  if (items.length === 0) return;
  const hasRaf = typeof requestAnimationFrame === 'function';
  let rafId = 0;
  let timerId: ReturnType<typeof setTimeout> | null = null;

  const schedule = (cb: () => void) => {
    if (hasRaf) {
      rafId = requestAnimationFrame(cb);
    } else {
      timerId = setTimeout(cb, 0);
    }
  };
  const cancel = () => {
    if (hasRaf) {
      cancelAnimationFrame(rafId);
    } else if (timerId) {
      clearTimeout(timerId);
      timerId = null;
    }
  };

  await new Promise<void>((resolve, reject) => {
    let i = 0;
    const step = () => {
      try {
        const end = Math.min(i + batchSize, items.length);
        for (; i < end; i++) {
          fn(items[i], i);
        }
        if (i < items.length) {
          schedule(step);
        } else {
          resolve();
        }
      } catch (e) {
        cancel();
        reject(e);
      }
    };
    schedule(step);
  });
}
