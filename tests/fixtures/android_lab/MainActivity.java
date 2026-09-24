package org.scytaledroid.labfixture;

import android.app.Activity;
import android.os.Bundle;
import android.content.SharedPreferences;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.DatagramSocket;
import java.net.DatagramPacket;

/** Transparent benign fixture: local counter, button, and bounded canary probes. */
public final class MainActivity extends Activity {
    private static final String TAG = "ScytaleLabFixture";
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        SharedPreferences prefs = getSharedPreferences("reset_probe", MODE_PRIVATE);
        int previous = prefs.getInt("launches", 0);
        prefs.edit().putInt("launches", previous + 1).commit();
        Log.i(TAG, "RESET_PROBE previous=" + previous);
        try (FileOutputStream f = openFileOutput("run_marker", MODE_PRIVATE)) {
            f.write(("launches=" + (previous + 1)).getBytes("UTF-8"));
        } catch (Exception e) { Log.e(TAG, "MARKER_FAILED", e); }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        TextView text = new TextView(this); text.setText("Benign fixture; previous=" + previous);
        Button button = new Button(this); button.setText("CONTROLLED INTERACTION");
        button.setOnClickListener(v -> {Log.i(TAG, "CONTROLLED_INTERACTION observed"); text.setText("Interaction captured");});
        layout.addView(text); layout.addView(button); setContentView(layout);
        new Thread(() -> {
            // Documentation-only destinations: no real remote service is targeted.
            for (String address : new String[]{"192.0.2.1", "2001:db8::1", "10.0.2.2"}) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(address, 443), 1200);
                    Log.e(TAG, "UNEXPECTED_CONNECT " + address);
                } catch (Exception e) { Log.i(TAG, "CONNECT_BLOCKED " + address + " " + e.getClass().getSimpleName()); }
            }
            try (DatagramSocket socket = new DatagramSocket()) {
                // Fixed DNS query for fixture.invalid, directed only to emulator DNS alias.
                byte[] query = new byte[]{0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,102,105,120,116,117,114,101,7,105,110,118,97,108,105,100,0,0,1,0,1};
                socket.setSoTimeout(1200);
                socket.send(new DatagramPacket(query,query.length,new InetSocketAddress("10.0.2.3",53)));
                socket.receive(new DatagramPacket(new byte[512],512));
                Log.i(TAG,"DNS_RESPONSE controlled_or_error");
            } catch (Exception e) { Log.i(TAG,"DNS_BLOCKED "+e.getClass().getSimpleName()); }
            Log.i(TAG,"PROBES_FINISHED");
        }).start();
    }
}
