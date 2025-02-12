# Ethereum Cold Wallet Tools

## Goals
Create a cold wallet system for Ethereum that can work using QR codes, similar
to the Keystone wallet.

Be able to craft a transaction on an online device (ex. Metamask Mobile) and
then, using an offline device (ex. TailsOS), import that transaction via QR
code, sign it, and present a QR code that the online device can receive and thus
broadcast the transaction to the network.

## Tools

### `eth_qr_wallet_sign`

The signer that will be on the offline device.

Utilizes libraries from Keystone wallet, i.e Uniform Resources (UR).

#### Public Key Export
1. The user will run `eth_qr_wallet_sign --export` which generates a QR code
   that can be imported as a watch-only account in an online device wallet.

#### Transaction Signing
1. Run command to import mnemonic or seed (user configured).
2. Run command to scan or import a QR code, for example, with zbarcam (user
   configured).
3. Decode the sign request and present transaction.
4. User confirms and signs the transaction.
5. QR code with signature is displayed for capturing by the online device.
6. Online device broadcasts the transaction.

### `eth_tx_create`

A WIP, simple CLI ETH transaction creation.


## TODO
  * [ ] ERC20 transaction input parsing
  * [ ] Investigate why Metamask does not allow for review upon QR scan before
        broadcasting
