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

Notes for BIND 9.16.35
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Compile-time settings enabled by the ``--with-tuning=large`` option
  for ``configure`` have been disabled by default.  This makes the
  memory usage in the resolver to be more aligned with the memory
  usage in BIND 9.11.  Previously used default compile-time settings
  in BIND 9.16 can be enabled by passing ``--with-tuning=large`` to
  ``configure``. :gl:`#3663`

Bug Fixes
~~~~~~~~~

- The RecursClients statistics counter could overflow in certain resolution
  scenarios. This has been fixed. :gl:`#3584`

- BIND would fail to start on Solaris-based systems with hundreds of CPUs. This
  has been fixed. ISC would like to thank Stacey Marshall from Oracle for
  bringing this problem to our attention. :gl:`#3563`

- In certain resolution scenarios quotas could be erroneously reached for
  servers, including the configured forwarders, resulting in SERVFAIL answers
  sent to the clients. This has been fixed. :gl:`#3598`

- When having Internet connectivity issues during the initial startup of
  ``named``, BIND resolver with ``dnssec-validation`` set to ``auto`` could
  enter into a state where it would not recover without stopping ``named``,
  manually deleting ``managed-keys.bind`` and ``managed-keys.bind.jnl`` files,
  and starting ``named`` again. :gl:`#2895`

- Fixed a crash that happens when you reconfigure a ``dnssec-policy``
  zone that uses NSEC3 to enable ``inline-signing``. :gl:`#3591`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
