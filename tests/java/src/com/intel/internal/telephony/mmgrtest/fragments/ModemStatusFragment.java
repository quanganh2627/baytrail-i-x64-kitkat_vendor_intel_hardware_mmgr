package com.intel.internal.telephony.mmgrtest.fragments;

import com.intel.internal.telephony.MmgrClientException;
import com.intel.internal.telephony.ModemEventListener;
import com.intel.internal.telephony.ModemNotification;
import com.intel.internal.telephony.ModemNotificationArgs;
import com.intel.internal.telephony.ModemStatus;
import com.intel.internal.telephony.ModemStatusManager;
import com.intel.internal.telephony.mmgrtest.R;
import com.intel.internal.telephony.mmgrtest.helpers.MessageBoxHelper;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

public class ModemStatusFragment extends Fragment implements
        ModemEventListener, OnClickListener {

    private TextView textViewClientStatus = null;
    private TextView textViewModemStatus = null;
    private TextView textViewLastNotification = null;
    private Button buttonRequestRecovery = null;
    private Button buttonRequestRestart = null;
    private Button buttonRequestShutdown = null;
    private Button buttonRequestLock = null;
    private Button buttonRequestRelease = null;

    private ModemStatusManager modemManager = null;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            this.modemManager = ModemStatusManager.getInstance();
            this.modemManager.subscribeToEvent(this, ModemStatus.ALL,
                    ModemNotification.ALL);
        } catch (Exception ex) {
            MessageBoxHelper.showException(this.getActivity(), ex);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        try {
            this.modemManager.disconnect();
            this.modemManager = null;
        } catch (Exception ex) {
            MessageBoxHelper.showException(this.getActivity(), ex);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {

        View ret = inflater.inflate(R.layout.modem_status, container, false);

        if (ret != null) {

            this.textViewClientStatus = (TextView) ret
                    .findViewById(R.id.textViewClientStatusValue);
            this.textViewModemStatus = (TextView) ret
                    .findViewById(R.id.textViewModemStatusValue);
            this.textViewLastNotification = (TextView) ret
                    .findViewById(R.id.textViewLastNotificationValue);

            this.buttonRequestRecovery = (Button) ret
                    .findViewById(R.id.buttonRequestRecovery);
            this.buttonRequestRestart = (Button) ret
                    .findViewById(R.id.buttonRequestRestart);
            this.buttonRequestShutdown = (Button) ret
                    .findViewById(R.id.buttonRequestShutdown);
            this.buttonRequestLock = (Button) ret
                    .findViewById(R.id.buttonRequestLock);
            this.buttonRequestRelease = (Button) ret
                    .findViewById(R.id.buttonRequestRelease);

            this.buttonRequestRecovery.setOnClickListener(this);
            this.buttonRequestRestart.setOnClickListener(this);
            this.buttonRequestShutdown.setOnClickListener(this);
            this.buttonRequestLock.setOnClickListener(this);
            this.buttonRequestRelease.setOnClickListener(this);
        }

        this.textViewClientStatus.setText("CONNECTING...");
        new AsyncConnectTask(this.modemManager, "MMGR Test")
                .execute((Void) null);

        return ret;
    }

    @Override
    public void onModemColdReset(ModemNotificationArgs arg) {
        if (this.textViewLastNotification != null) {
            this.textViewLastNotification.setText("MODEM COLD RESET");
        }
    }

    @Override
    public void onModemCoreDump(ModemNotificationArgs arg) {
        if (this.textViewLastNotification != null) {
            this.textViewLastNotification.setText("MODEM CORE DUMP");
        }
    }

    @Override
    public void onModemWarmReset(ModemNotificationArgs arg) {
        if (this.textViewLastNotification != null) {
            this.textViewLastNotification.setText("MODEM WARM RESET");
        }
    }

    @Override
    public void onPlatformReboot(ModemNotificationArgs arg) {
        if (this.textViewLastNotification != null) {
            this.textViewLastNotification.setText("PLATFORM REBOOT");
        }
    }

    @Override
    public void onModemShutdown(ModemNotificationArgs arg) {
        if (this.textViewLastNotification != null) {
            this.textViewLastNotification.setText("MODEM SHUTDOWN");
        }
    }

    @Override
    public void onModemDead() {
        if (this.textViewModemStatus != null) {
            this.textViewModemStatus.setText("MODEM DEAD");
        }
    }

    @Override
    public void onModemDown() {
        if (this.textViewModemStatus != null) {
            this.textViewModemStatus.setText("MODEM DOWN");
        }
    }

    @Override
    public void onModemUp() {
        if (this.textViewModemStatus != null) {
            this.textViewModemStatus.setText("MODEM UP");
        }
    }

    @Override
    public void onClick(View view) {
        if (view != null) {

            try {
                switch (view.getId()) {
                case R.id.buttonRequestRecovery:
                    if (this.modemManager != null) {
                        this.modemManager.recoverModem();
                    }
                    break;
                case R.id.buttonRequestRestart:
                    if (this.modemManager != null) {
                        this.modemManager.restartModem();
                    }
                    break;
                case R.id.buttonRequestShutdown:
                    if (this.modemManager != null) {
                        this.modemManager.shutdowModem();
                    }
                    break;
                case R.id.buttonRequestLock:
                    if (this.modemManager != null) {
                        this.modemManager.acquireModem();
                    }
                    break;
                case R.id.buttonRequestRelease:
                    if (this.modemManager != null) {
                        this.modemManager.releaseModem();
                    }
                    break;
                }
            } catch (Exception ex) {
                MessageBoxHelper.showException(this.getActivity(), ex);
            }
        }
    }

    private class AsyncConnectTask extends AsyncTask<Void, Integer, Boolean> {

        private Exception lastException = null;
        private ModemStatusManager manager = null;
        private String clientName = "";

        public AsyncConnectTask(ModemStatusManager modemManager,
                String clientName) {
            this.manager = modemManager;
            this.clientName = clientName;
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            Boolean ret = false;

            if (this.manager != null) {
                try {
                    this.manager.connect(clientName);
                    ret = true;
                } catch (MmgrClientException ex) {
                    this.lastException = ex;
                    ret = false;
                }
            }
            return ret;
        }

        @Override
        protected void onPostExecute(Boolean result) {
            super.onPostExecute(result);

            if (result) {
                ModemStatusFragment.this.setUIConnectedMode();
            } else {
                ModemStatusFragment.this.setUIDisconnectedMode();
                if (this.lastException != null) {
                    MessageBoxHelper.showException(
                            ModemStatusFragment.this.getActivity(),
                            this.lastException);
                }
            }
        }
    }

    private void setUIConnectedMode() {

        if (this.textViewClientStatus != null) {
            this.textViewClientStatus.setText("CONNECTED");
        }
        if (this.buttonRequestLock != null) {
            this.buttonRequestLock.setEnabled(true);
        }
        if (this.buttonRequestRecovery != null) {
            this.buttonRequestRecovery.setEnabled(true);
        }
        if (this.buttonRequestRelease != null) {
            this.buttonRequestRelease.setEnabled(true);
        }
        if (this.buttonRequestRestart != null) {
            this.buttonRequestRestart.setEnabled(true);
        }
        if (this.buttonRequestShutdown != null) {
            this.buttonRequestShutdown.setEnabled(true);
        }
    }

    private void setUIDisconnectedMode() {

        if (this.textViewClientStatus != null) {
            this.textViewClientStatus.setText("DISCONNECTED");
        }
        if (this.buttonRequestLock != null) {
            this.buttonRequestLock.setEnabled(false);
        }
        if (this.buttonRequestRecovery != null) {
            this.buttonRequestRecovery.setEnabled(false);
        }
        if (this.buttonRequestRelease != null) {
            this.buttonRequestRelease.setEnabled(false);
        }
        if (this.buttonRequestRestart != null) {
            this.buttonRequestRestart.setEnabled(false);
        }
        if (this.buttonRequestShutdown != null) {
            this.buttonRequestShutdown.setEnabled(false);
        }
    }
}
