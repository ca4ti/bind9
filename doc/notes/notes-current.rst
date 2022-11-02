.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Notes for BIND 9.19.7
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- ``check-svcb`` has been added to control the checking of additional
  constraints on SVBC records.  This change impacts on ``named``,
  ``named-checkconf``, ``named-checkzone``, ``named-compilezone``
  and ``nsupdate``.  :gl:`#3576`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- On Linux, libcap is now required dependency to help us keep needed
  privileges. :gl:`#3583`

Bug Fixes
~~~~~~~~~

- BIND would fail to start on Solaris-based systems with hundreds of CPUs. This
  has been fixed. ISC would like to thank Stacey Marshall from Oracle for
  bringing this problem to our attention. :gl:`#3563`

- In certain resolution scenarios quotas could be erroneously reached for
  servers, including the configured forwarders, resulting in SERVFAIL answers
  sent to the clients. This has been fixed. :gl:`#3598`

- The port in remote servers such as in :any:`primaries` and
  :any:`parental-agents` could be wrongly configured because of an inheritance
  bug. :gl:`#3627`

- When having Internet connectivity issues during the initial startup of
  ``named``, BIND resolver with :any:`dnssec-validation` set to ``auto`` could
  enter into a state where it would not recover without stopping ``named``,
  manually deleting ``managed-keys.bind`` and ``managed-keys.bind.jnl`` files,
  and starting ``named`` again. :gl:`#2895`

- Fix bugs related to ``inline-signing`` zones that are subject to a
  multisigner model (RFC 8901). In some cases it was not possible to update
  the zone with a DNSKEY, CDS or CDNSKEY from the other provider, or the
  record would be removed again after a re-sign of the zone. :gl:`#2710`
