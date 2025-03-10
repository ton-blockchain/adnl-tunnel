# ADNL Tunnel

ADNL Tunnel is an implementation of an ADNL proxy that allows you to rent a gateway and tunnel your ADNL traffic through other servers, with the option to pay for traffic via the TON Payment Network.

**This can tunnel only ADNL packets, and not works like VPN, it also cannot work as HTTP proxy, this tool is made to protect from direct attacks in decentralized TON network**

## Compile

Install golang 1.23.3+

Run `make binary`, it will compile server binary.

If you want to compile native static library to integrate into some c++ project run `make library`

## Setup Server

1. Run the executable.  
   This will generate a `config.json` file in the working directory.

2. Check the configuration file and make sure that the `ExternalIP` field contains the correct value of your external IP address.  
   If it is empty, you need to open the necessary ports and ensure that your provider gives you a public and static IP.

3. Share ADNL ID displayed in console to your users, so they can tunnel their packets through your server.

### Accepting Payments

If you want to charge users for packet tunneling:

1. Set `PaymentsEnabled` to `true` in the config file.
2. Set `MinPricePerPacketRoute` and `MinPricePerPacketInOut` values to define the price per packet in nano TON.
3. Restart the service.
4. Top up the wallet address displayed in the console.
5. On the first run, you will be prompted to enter the key of the payment node you want to connect to.
6. Enter the payment node key to deploy the contract.
7. Request the payment node service to deposit a reserve amount into this contract.
8. Once the payment contract has a deposit, you can start accepting payments.

## Supported commands

`speed` - every second shows packets per second for each active tunnel

`balance` - shows current earned amount

`capacity` - shows how much deposit left from payment node (it transforms to balance, sho it should always be positive to accept coins)

## Client usage

It depends on specific tool, for example it is integrated into TON Node and can protect validators from DDoS attacks, see how to connect in it's repository.
