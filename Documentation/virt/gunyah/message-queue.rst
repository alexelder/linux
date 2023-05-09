      |               |         |                 |         |               |
      |               |         |                 |         |               |
      +---------------+         +-----------------+         +---------------+

Gunyah message queues are exposed as mailboxes. To create the mailbox, create
a mbox_client and call `gh_msgq_init()`. On receipt of the RX_READY interrupt,
all messages in the RX message queue are read and pushed via the `rx_callback`
of the registered mbox_client.

.. kernel-doc:: drivers/mailbox/gunyah-msgq.c
   :identifiers: gh_msgq_init
