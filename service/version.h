/* Modem Manager - version file history
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
 ** ============================================================================
 ** MMGR version:
 **
 ** The MMGR versioning convention uses three digits as the following scheme:
 ** <project code>.<Major version>.<Minor version>
 **
 ** 2.1.0  - 2012-02-01 - BZ 19146 - Provide the STMD version at Boot
 ** 2.1.1  - 2012-02-01 - BZ 19913 - Update to have XLOG dump in AP log
 ** 2.1.2  - 2012-02-03 - BZ 21570 - Replace mcdr binary by a dynamic library
 ** 2.1.3  - 2012-02-03 - BZ 21227 - Echo mode patch
 ** 2.1.4  - 2012-02-06 - BZ 21228 - failures of open() of /dev/ttyIFX0 at boot
 ** 2.1.5  - 2012-02-17 - BZ 23303 - Fix minor issues
 ** 2.1.6  - 2012-02-20 - BZ 11438 - Investigate FCS errors and Frame overflows
 ** 2.1.7  - 2012-02-21 - BZ 20428 - use sysfs to perform a cold reset
 ** 2.1.8  - 2012-02-27 - BZ 22222 - STMD recovery mechanism improvement
 ** 2.1.9  - 2012-02-28 - BZ 25135 - sysfs force_cold_boot update
 ** 2.1.10 - 2012-03-01 - BZ 25751 - wake up the modem after a REQUEST_SHUTDOWN
 ** 2.1.11 - 2012-03-09 - BZ 23091 - klocwork critical issues removal
 ** 2.1.12 - 2012-03-14 - BZ 25917 - change included kernel header for bioanic
 ** 2.1.13 - 2012-03-14 - BZ 20095 - create an empty file named mshutdown.txt
 ** 2.1.14 - 2012-03-14 - BZ 27445 - variables access concurrency improvement
 ** 2.1.15 - 2012-03-28 - BZ 27554 - escalation recovery logs improvement
 ** 2.1.16 - 2012-03-28 - BZ 29413 - mcdr improvements
 ** 2.1.17 - 2012-03-29 - BZ 29704 - logs improvement
 ** 2.1.18 - 2012-04-12 - BZ 26755 - limit the platform reboot retry
 ** 2.1.19 - 2012-04-17 - BZ 32439 - prevent crash when writing to closed socket
 ** 2.1.20 - 2012-04-19 - BZ 32454 - code clean-up: dead code, coding rules, ...
 ** 2.1.21 - 2012-04-25 - BZ 33211 - Modem and MUX frame size configuration
 ** 2.1.22 - 2012-05-15 - BZ 35718 - sysfs path update to handle hsi dlp driver
 ** 2.1.23 - 2012-05-23 - BZ 33029 - recovery escalation process rework
 ** 2.1.24 - 2012-05-25 - BZ 25361 - use of wakelock preventing to go to sleep
 ** 3.1.0  - 2012-06-06 - BZ 40219 - improve wakelock removal
 ** 3.1.1  - 2012-06-20 - BZ 40175 - Modem SW EXCEPTION without core dump
 ** 3.1.2  - 2012-06-01 - BZ 33155 - run STMD with system privileges
 ** 3.1.3  - 2012-06-25 - BZ 39788 - REQUEST_SHUTDOWN: reduce power consumption
 ** 3.1.7  - 2012-07-23 - BZ 47713 - configuration file rewrite
 ** 3.1.8  - 2012-07-26 - BZ 43959 - bugfix: create mshutdown.txt before reboot
 ** 3.1.9  - 2012-08-16 - BZ 52592 - WA: remove mutex in send_at before POLLHUP management
 ** 3.1.10 - 2012-08-23 - BZ 52843 - STMD shall request HSI driver to turn off
 ** 3.1.11 - 2012-07-31 - BZ 46422 - detect coredump protocol for mcdr
 ** 3.1.12 - 2012-09-18 - BZ 56671 - open libmcdr dynamically
 ** 3.1.13 - 2012-09-18 - BZ 40854 - Clean up Xlog buffer displaying
 ** 3.1.14 - 2012-10-03 - BZ 56972 - Move logs partition mount point to /logs
 ** 3.1.15 - 2012-08-23 - BZ 56457 - new broadcast intent messages
 ** 3.1.16 - 2012-10-05 - BZ 60275 - Set default umask to configure file permission access
 ** 3.1.17 - 2012-10-16 - BZ 62543 - Automatically detect HSI driver
 ** 3.2.1  - 2012-08-22 - BZ 47717 - MMGR rework
 ** 3.2.2  - 2012-10-25 - BZ 60084 - mmgr client library and socket improvements
 ** 3.2.3  - 2012-10-25 - BZ 64484 - reset modem after open failure
 ** 3.2.4  - 2012-10-26 - BZ 58703 - Disable burst mode
 ** 3.2.5  - 2012-11-30 - BZ 71835 - fix modem_reset_delay configuration
 ** 3.2.6  - 2012-11-12 - BZ 40361 - Implements Modem Control Driver
 ** 3.2.6  - 2013-01-14 - BZ 80134 - fix create_empty_file argument flags
 ** 3.2.7  - 2013-01-11 - BZ 78991 - fix off by one error in send_at() function
 ** 3.2.8  - 2013-01-18 - BZ 40361 - implement Modem Control Driver
 ** 3.2.9  - 2013-01-18 - BZ 79757 - close tty before core dump management
 ** 3.2.10 - 2013-01-18 - BZ 71590 - do not open tty in blocking mode
 ** 3.2.11 - 2013-01-30 - BZ 81140 - retry to open tty when access is denied
 ** 3.2.12 - 2013-02-06 - BZ 85009 - send MODEM_DOWN before notification
 ** 3.2.13 - 2013-02-06 - BZ 85469 - do not report MRESET after core dump
 ** 3.2.14 - 2013-02-06 - BZ 85207 - fix core dump retrieval
 ** 3.2.15 - 2013-02-06 - BZ 82064 - remove NO_RESOURCE_RELEASE timer
 ** 3.2.16 - 2013-02-07 - BZ 82892 - set MCD state to OFF before modem shutdown
 ** 3.2.17 - 2013-02-14 - BZ 86071 - remove MODEM OFF from escalation recovery
 ** 3.2.18 - 2013-02-14 - BZ 86674 - client API: flight mode enhancement
 ** 3.2.19 - 2013-02-21 - BZ 88488 - fix MODEM DOWN event
 ** 3.2.20 - 2013-02-22 - BZ 88670 - fix client notification
 ** 3.2.21 - 2013-02-22 - BZ 88604 - fix setting MCD modem state to OFF
 ** 3.2.22 - 2013-02-26 - BZ 87509 - REVERT: fix setting MCD modem state to OFF
 ** 3.2.23 - 2013-02-26 - BZ 87509 - REVERT: fix client notification
 ** 3.2.24 - 2013-02-26 - BZ 87509 - REVERT: fix MODEM DOWN event
 ** 3.2.25 - 2013-02-26 - BZ 87509 - REVERT: client API: flight mode enhancement
 ** 3.2.26 - 2013-02-18 - BZ 87509 - REVERT: remove MODEM OFF from escalation recovery
 ** 4.1.1  - 2013-02-07 - BZ 76423 - modem flashless and HSIC introduction
 ** 4.1.2  - 2013-02-08 - BZ 86071 - fix escalation recovery
 ** 4.1.3  - 2013-02-11 - BZ 86208 - MCD early boot removal
 ** 4.1.4  - 2013-02-18 - BZ 87518 - read flashless.conf file at boot-up
 ** 4.1.5  - 2013-02-19 - BZ 87729 - remove MODEM OFF from escalation recovery
 ** 4.1.6  - 2013-02-19 - BZ 87729 - client API: flight mode enhancement
 ** 4.1.7  - 2013-02-26 - BZ 87729 - fix MODEM DOWN event handling
 ** 4.1.8  - 2013-02-26 - BZ 87729 - fix client notifications
 ** 4.1.9  - 2013-02-26 - BZ 87729 - fix setting MCD modem state to OFF
 ** 4.1.10 - 2013-02-26 - BZ 89391 - fix communication with clients
 ** 4.1.11 - 2013-03-01 - BZ 90373 - fix comments for patch #91071
 ** 4.1.12 - 2013-02-28 - BZ 90123 - add additional product customization
 **
 ** ============================================================================
 */

/* MODULE_VERSION: don't forget to update the header */
#define MODULE_VERSION "4.1.12"
