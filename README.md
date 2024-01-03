# SPBE - A Sum of Products based Broadcast Encryption Scheme

The problem of Broadcast Encryption (BE) consists in broadcasting an encrypted message to a large number of users or receiving devices in such a way that the emitter of the message can control which of the users can or cannot decrypt it.

Since the early 1990's, the design of BE schemes has received significant interest and many different concepts were proposed. A major breakthrough was achieved by Naor, Naor and Lotspiech (CRYPTO 2001) by partitioning cleverly the set of authorized users and associating a symmetric key to each subset. Since then, while there have been many advances in public-key based BE schemes, mostly based on bilinear maps, little was made on symmetric cryptography.

In this project, we design a new symmetric-based BE scheme, named SPBE, that relies on logic optimization and consensual security assumptions. It is competitive with the work of Naor et al. and provides a different tradeoff: the bandwidth requirement is significantly lowered at the cost of an increase in the key storage.

Intellectual property
---------------------

Part of the code falls into some intellectual property. It will be made available online as soon as we obtain that it is free of use, modification and redistribution.
