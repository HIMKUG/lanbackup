package com.backup.mobile;

import android.os.Bundle;
import android.view.View;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // WebView 合成走 GPU：滚动/动画更流畅（滚动容器与动画元素）
        getWindow().getDecorView().setLayerType(View.LAYER_TYPE_HARDWARE, null);
    }
}
