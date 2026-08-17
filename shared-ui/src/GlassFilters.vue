<template>
  <!-- 全局液态玻璃折射滤镜（#glass-distortion）：
       已删除 feSpecularLighting/feComposite 死链（输出未被引用，纯白算）；
       stdDeviation 3→1、scale 200→100 降采样；sRGB 色彩空间省逐图元转换。 -->
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

      <feComponentTransfer in="turbulence" result="mapped">
        <feFuncR type="gamma" amplitude="1" exponent="10" offset="0.5" />
        <feFuncG type="gamma" amplitude="0" exponent="1" offset="0" />
        <feFuncB type="gamma" amplitude="0" exponent="1" offset="0.5" />
      </feComponentTransfer>

      <feGaussianBlur in="turbulence" stdDeviation="1" result="softMap" />

      <feDisplacementMap
        in="SourceGraphic"
        in2="softMap"
        scale="100"
        xChannelSelector="R"
        yChannelSelector="G"
      />
    </filter>
  </svg>
</template>
