<template>
  <!-- 全局液态玻璃折射滤镜（#glass-distortion）：
       性能优化瘦身版（已与用户确认）：
       · 移除未实际接入输出的 feComponentTransfer / feSpecularLighting / feComposite
         （原链 litImage/mapped 结果均被丢弃，GPU 仍白算，去掉无视觉影响）
       · feDisplacementMap scale 200→80（折射强度略减，质感保留） -->
  <svg style="display: none" aria-hidden="true">
    <filter
      id="glass-distortion"
      x="0%"
      y="0%"
      width="100%"
      height="100%"
      filterUnits="objectBoundingBox"
      color-interpolation-filters="sRGB"
    >
      <feTurbulence
        type="fractalNoise"
        baseFrequency="0.001 0.005"
        numOctaves="1"
        seed="17"
        result="turbulence"
      />

      <feGaussianBlur in="turbulence" stdDeviation="3" result="softMap" />

      <feDisplacementMap
        in="SourceGraphic"
        in2="softMap"
        scale="80"
        xChannelSelector="R"
        yChannelSelector="G"
      />
    </filter>
  </svg>
</template>
