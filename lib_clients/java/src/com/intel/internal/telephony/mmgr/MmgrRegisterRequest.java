/* Android Modem Status Client API
 *
 * Copyright (C) Intel 2012
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.intel.internal.telephony.mmgr;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import android.util.Log;

import com.intel.internal.telephony.ModemRequestArgs;

public class MmgrRegisterRequest extends ModemRequestArgs {

    private String clientName = "";
    private int subscribedEvents = 0;

    public MmgrRegisterRequest(String clientName, int subscribedEvents) {
        this.setClientName(clientName);
        this.setSubscribedEvents(subscribedEvents);
    }

    public String getClientName() {
        return this.clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName.substring(0,
                Math.min(63, clientName.length()));
    }

    public int getSubscribedEvents() {
        return this.subscribedEvents;
    }

    public void setSubscribedEvents(int subscribedEvents) {
        this.subscribedEvents = subscribedEvents;
    }

    @Override
    public byte[] getFrame() {
        ByteBuffer ret = ByteBuffer.allocate(64 + 4);

        byte[] clientNameBytes = null;

        try {
            clientNameBytes = this.clientName.getBytes("US-ASCII");
        } catch (UnsupportedEncodingException e) {
            // TODO tag
            Log.e("TODO", "Ascii encoding not supported");
        }
        if (clientNameBytes != null) {
            ret.put(clientNameBytes, 0, clientNameBytes.length);
        }
        int reversedEvent = Integer.reverseBytes(this.subscribedEvents);
        ret.putInt(64, reversedEvent);

        return ret.array();
    }

    @Override
    public String getName() {
        return "RegisterRequest";
    }
}
