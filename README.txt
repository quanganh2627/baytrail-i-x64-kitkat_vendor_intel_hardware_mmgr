/* Modem Manager (MMGR) - README FILE
**
** Copyright (C) Intel 2012
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
**
*/

Summary
================================
1) Overview
2) MMGR interface
  2.1) Resource allocation
  2.2) Modem events
  2.3) Modem notifications
  2.4) Client requests
  2.5) Request acknowledgement
    2.5.1) Modem manager acknowledge requests
    2.5.2) Client acknowledge requests
  2.6) MMGR client library
    2.6.1) Library link
    2.6.2) Code example
3) Java Intent messages


1) Overview
================================
This README file provides a low-level overview of the interface given by MMGR to
its clients. Clients shall use the MMGR client library. This description is more
to add details on the interface provided by modem manager. It is mandatory for
any processes accessing the modem to utilize this interface. No gsmtty file
descriptors should be opened (and hence no data sent to the modem) before MMGR
declares modem ready. This interface is currently socket based but it can change
one day.

MMGR also uses Java intent broadcast messages to inform Java applications of
modem status. These messages are only broadcasted in eng and userdebug builds
ONLY. This is not the official way to get the modem status.
It's not possible to perform a request to the modem with this interface, it's
a unidirectional communication mode.
Telephony Event Notifier uses those messages for example.


2) MMGR interface
================================
MMGR provides a single socket accessible to radio group members and system user
only. The goal of this socket is to inform all clients of modem status and
provide a way for all its clients to ask for special operations.

The name of this socket is defined in the mmgr.h header file by
the MMGR_SOCKET_NAME constant.

Socket name and constant request values are subject to change. Please include
the header file in your project instead of redefine the values.

Once connected to MMGR socket, client should declare its name before any
request. The name size is CLIENT_NAME_LEN characters maximum.

Clients should also provide their events subscription mask. This mask is 32
bits long. To subscribe to an event, the bit matching the event id must be
set to 1.

A client is considered connected only if it had send its name and its
subscription mask.

A MMGR message _ALWAYS_ follow this frame:
  * request id (unsigned int)
  * timestamp (unsigned int)
  * data length (unsigned int)
  * data (only if data length > 0)


  2.1) Resource allocation
  ------------------------------
  Clients who need the modem or the SIM should declare themselves to the modem
  manager. Once they don’t need neither the Modem nor the SIM anymore, they
  should inform the Modem Manager. This resource allocation is used for power
  saving. That's why, all clients must therefore pay the utmost attention to
  them.
  In flight mode, if no client has used the modem for a while and if they have
  released the resource, the modem will be completely powered off. The timeout
  is configurable thanks to mmgr configuration file.

  - E_MMGR_RESOURCE_ACQUIRE: Request used by the clients that don’t want the
  Modem to go to OFF because they need the Modem or the SIM. After reception
  of this message and if the modem is completely off, the modem will be powered
  on.
  NB: this request will be rejected if modem is OUT OF SERVICE.

  - E_MMGR_RESOURCE_RELEASE: Request used by the clients that have already
  allocated the modem and that don’t need neither the Modem nor the SIM anymore.


  2.2) Modem events
  ------------------------------
  Modem events are broadcasted by MMGR to its clients using the socket. They are
  used to provide the modem status. Once client has provided its name after its
  connection, MMGR will systematically send the current modem status to it (if
  the client is registered to this event).
  After, MMGR will send the modem status only when there is change on it.

  The following status can be sent:

  - E_MMGR_EVENT_MODEM_DOWN: this status indicates that modem is OFF or is
    being recovered: in this state, its interfaces (/dev/gsmtty ports) are not
    usable. When this status is received by MMGR's clients, they must close
    (or do not open) modem ports. This is the default status when the platform
    boots. Switch to this status can occur when MMGR detects a reset or a
    core-dump or when the MMGR performs a modem shutdown or a modem reset.
    NB: this message is sent just before MUX closing

  - E_MMGR_EVENT_MODEM_UP: this status indicates that the modem and its
    interfaces are ready to be used. When this status is received, clients
    of MMGR can open modem ports and use them. Switch to this status can
    occur when boot initialization of modem is done or after the end of a
    modem reset.

  - E_MMGR_EVENT_MODEM_OUT_OF_SERVICE: this status indicates that modem is
    out of service and that it cannot be recovered: in this state,
    its interfaces (/dev/gsmtty ports) are not usable.
    Modem manager will completely power off the modem.


  2.3) Modem notifications
  ------------------------------
  Modem Notifications are broadcasted by MMGR to its clients after a modem
  status update. It provides information about which operation will be
  performed.
  Some notifications must be answered by an acknowledge message
  by all clients.

  The following notifications can be sent:

  - E_MMGR_NOTIFY_MODEM_WARM_RESET: this status indicates that MMGR will
    perform a modem WARM reset. Once the client has received this message,
    it should close all /dev/gsmtty devices.
    NB: MMGR will transmit E_MMGR_EVENT_MODEM_DOWN right after
    the E_MMGR_NOTIFY_MODEM_WARM_RESET transmission. No timeout limit between
    those messages.

  - E_MMGR_NOTIFY_MODEM_COLD_RESET: this status indicates that MMGR will
    perform a modem COLD reset. This operation requires that all clients
    configure electrically their HW interfaces with the Modem for a temporary
    Modem OFF state . That’s why, MMGR waits for all clients' approval before
    performing this operation. A timeout of 1s is used to avoid client’s
    lack of answer.
    NB: MMGR will transmit E_MMGR_EVENT_MODEM_DOWN once all clients have sent
    their acknowledge message or if timeout expired.

  - E_MMGR_NOTIFY_MODEM_SHUTDOWN: this status indicates that the modem will
    be completely shutdown. This message is sent before a modem complete
    shutdown. It requires that all clients have released the resource (§2.1)
    and haven't used the modem for a while after that.
    The clients should configure electrically their HW interfaces with
    the modem for a modem OFF state. A timeout of 1s is used to avoid client’s
    lack of answer.
    NB: MMGR will transmit E_MMGR_EVENT_MODEM_DOWN once all clients have sent
    their acknowledge message or if timeout expired.

  - E_MMGR_NOTIFY_PLATFORM_REBOOT: this status indicates that modem manager
    will reboot the platform

  - E_MMGR_NOTIFY_CORE_DUMP: a modem core dump is available

  2.4) Client requests
  ------------------------------
  The goal of these requests is to give the possibility for MMGR's clients to
  ask for some special operations. A request is composed of a request id and
  a timestamp.

  In MOS, the following requests are available:

  - E_MMGR_REQUEST_SET_NAME: used to provide client's name

  - E_MMGR_REQUEST_SET_EVENTS: used to provide client's subscription mask

  - E_MMGR_REQUEST_MODEM_RECOVERY: this request is used to request a modem
    recovery when the client detects a modem fatal failure (a timeout for
    example). This request will go to the modem recovery escalation process
    and will result most of the time into a modem reset.
    NB1: this request will be rejected if modem is OUT OF SERVICE.
    NB2: if a reset escalation is already ongoing, the client will receive an
    ACK but a second reset will not be performed.

  - E_MMGR_REQUEST_MODEM_RESTART: this request is used to ask for a modem
    restart. A modem COLD RESET is performed outside of modem reset escalation
    recovery. This is a specific use case. Please do not use it except if you
    know what you do.
    This request is accepted even if modem cold reset feature is disabled.
    Before performing the modem cold reset, MMGR will send the cold reset
    notification and will wait for client's answers.
    NB: this request will be rejected if modem is OUT OF SERVICE.

  - E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN: this request is used to completely
    shutdown the modem even if the resource is not released (§2.1). Modem
    manager will sent E_MMGR_NOTIFY_MODEM_SHUTDOWN notification and shutdown
    the modem.
    If the MMGR has already received this request, same request from any
    clients will be rejected.
    NB: this request will be rejected if modem is OUT OF SERVICE.

  NB: Requests performed during Modem Escalation recovery are accepted but
  nothing is done.

  A client request should be composed of the request id plus a timestamp
  (in seconds).


  2.5) Request acknowledgement
  ------------------------------
  To improve the communication, an acknowledge mechanism is used.

    2.5.1) Modem manager acknowledge requests
    - - - - - - - - - - - - - - - - - - - - -
    Requests sent by a client are ALWAYS acknowledged by modem manager.
    - E_MMGR_ACK: Client request has been accepted
    - E_MMGR_NACK: Client request has been rejected

    2.5.2) Client acknowledge requests
    - - - - - - - - - - - - - - - - - - - - -
    Those messages are used to answer to a notification which waits for
    acknowledge from the client.

    All clients connected to MMGR socket must handle these messages:
    - E_MMGR_ACK_MODEM_COLD_RESET: All clients must send this message in answer
      to an E_MMGR_NOTIFY_MODEM_COLD_RESET notification.

    - E_MMGR_ACK_MODEM_SHUTDOWN: All clients must send this message in answer
      to an E_MMGR_NOTIFY_MODEM_SHUTDOWN notification.


  2.6) MMGR client library
  ------------------------------
  MMGR provides a C shared client library to handle the MMGR interface.
  This library avoids code duplication in clients, inconsistencies, bugs, etc.
  It also provides abstraction of the Modem Manager interface implementation.
  Currently MMGR interface is socket based but it can change one day...
  *****************************************************************************
  ***          You should use it instead of writing your own code.          ***
  *****************************************************************************

    2.6.1) Library link
    - - - - - - - - - - - - - - - - - - - - -
    To use the mmgr client library, you should include the mmgr_client.h
    and statically link the library to your binary.

    Android.mk file extract:
    ~~~~~~~~~~~~~~~~~~~~~~~~
    LOCAL_SHARED_LIBRARIES += libmmgrcli.h

    2.6.2) Code example
    - - - - - - - - - - - - - - - - - - - - -
    Mmgr client library provides an API based on events handling. To use it,
    you have to:
    * First, clients have to subscribe to events they want by providing a
      callback function. When a subscribed event occurs, the callback function
      is called.
    * Second, clients should connect to mmgr. They should provide their name
      and a pointer to a structure they want, a context for example.
      The name should not exceed 64 characters.
      The client is responsible of the context management (allocation,
      deallocation, etc.)
      The callback function should not exceed 1s.

    Code example:
    ~~~~~~~~~~~~~~~~~~~~~~~~
    int mdm_dwn(mmgr_cli_event_t *ev)
    {
        /* do here whatever you need */
    }

    int mdm_up(mmgr_cli_event_t *ev)
    {
        /* do here whatever you need */
    }

    int mdm_cld_rst(mmgr_cli_event_t *ev)
    {
        my_struct_name *ctx = (comm_mdm *)ev->context;
        mmgr_cli_requests_t request = { .id = E_MMGR_ACK_MODEM_SHUTDOWN };
        mmgr_cli_send_msg(ctx->mmgr_hdl, &request);
        return 0;
    }

    int mdm_cld_rst(mmgr_cli_event_t *ev)
    {
        my_struct_name *ctx = (comm_mdm *)ev->context;
        mmgr_cli_requests_t request = { .id = E_MMGR_ACK_MODEM_COLD_RESET };
        mmgr_cli_send_msg(ctx->mmgr_hdl, &request);
        return 0;
    }
    int configure_mmgr(char *name, struct my_struct_name *context)
    {
        mmgr_subscribe(E_MMGR_EVENT_MODEM_UP, up_hdler);
        mmgr_subscribe(E_MMGR_EVENT_MODEM_DOWN, dwn_hdler);
        mmgr_connect(name, context);
        return EXIT_SUCCESS;
    }

    int main(...)
    {
        char name[] = "my_app_name";
        struct my_struct_name ctx;
        mmgr_cli_handle_t *mmgr_hdl;

        mmgr_cli_create_handle(&ctx.mmgr_hdl, name, &ctx);
        mmgr_cli_subscribe_event(ctx.mmgr_hdl, mdm_up, E_MMGR_EVENT_MODEM_UP);
        mmgr_cli_subscribe_event(ctx.mmgr_hdl, mdm_dwn,
                E_MMGR_EVENT_MODEM_DOWN);
        mmgr_cli_subscribe_event(ctx.mmgr_hdl, mdm_cld_rst,
                E_MMGR_NOTIFY_MODEM_COLD_RESET);

        mmgr_cli_subscribe_event(ctx.mmgr_hdl, mdm_shtdwn,
                E_MMGR_NOTIFY_MODEM_SHUTDOWN);

        /* ... */

        mmgr_cli_disconnect(ctx.mmgr_hdl);
        mmgr_cli_delete_handle(ctx.mmgr_hdl);
        return 0;
    }


3) Java Intent messages
================================
MMGR also uses Java intent broadcast messages to inform Java applications of
modem status.

Below is the list of intents:
  - com.intel.action.CORE_DUMP_WARNING: MMGR is retrieving a core dump
  - com.intel.action.CORE_DUMP_COMPLETE: MMGR core dump retrieval has finished
    (badly or correctly)
  - com.intel.action.MODEM_OUT_OF_SERVICE: MMGR declares modem out of service
  - com.intel.action.PLATFORM_REBOOT: MMGR notifies that platform will be
    rebooted
  - com.intel.action.MODEM_WARM_RESET: notifies modem WARM reset operation
  - com.intel.action.MODEM_COLD_RESET: notifies modem COLD reset operation
  - com.intel.action.MODEM_UNSOLICITED_RESET: modem self-reset
  - com.intel.action.MODEM_NOT_RESPONSIVE: modem reset by client
