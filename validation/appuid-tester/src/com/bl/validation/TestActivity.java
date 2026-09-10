package com.bl.validation;

import android.app.Activity;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;

public class TestActivity extends Activity {
    static { System.loadLibrary("bltester"); }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String result = runTests();
        try {
            File f = new File(getExternalFilesDir(null), "results.txt");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(result.getBytes());
            fos.close();
        } catch (Exception e) { }
        finish();
    }

    private native String runTests();
}
